"""Defines classes that are used to create server utilities."""
import collections
from datetime import datetime
import functools
import gzip
import json
import logging
import multiprocessing
import os
import random
import shutil
import signal
import socket
import time

from boltons import iterutils
import inflection
import schedule
import zmq
from zmq import auth
from zmq.auth import thread

from shared import conf
from server import distribution
from server import objects
from shared import errors
from shared import utils


class Broker(multiprocessing.Process):
    """Defines a Strelka broker.

    Brokers are intermediary server processes that control routing between
    clients and workers. All settings are derived from the strelka.yml
    configuration file. Brokers can optionally be set to encrypt and
    authenticate connections from clients.

    Attributes:
        daemon_cfg: Dictionary containing the parsed "daemon" section
            from strelka.yml.
        network_cfg: Dictionary containing the parsed "network" sub-section
            from strelka.yml.
        broker_cfg: Dictionary containing the parsed "broker" sub-section
            from strelka.yml.
        curve_authenticator: ZMQ Curve authenticator. Used to authenticate
            client connections to the Broker if Curve encryption is enabled.
            Defaults to None.
        worker_pool: Ordered Dictionary that stores running workers. Brokers
            are configured to prune shutdown/dead workers from the pool on
            a schedule.
        request_socket_port: Network port that clients send file requests over.
            Defaults to 5558.
        task_socket_port: Network port that workers receive file tasks over.
            Defaults to 5559.
        poller_timeout: Amount of time (in milliseconds) that the broker polls
            for client requests and worker statuses. Defaults to
            1000 milliseconds.
        broker_secret_key: Location of the broker Curve secret key
            certificate. If set to None, then Curve encryption is not enabled.
            Defaults to None.
        client_public_keys: Location of the directory of Curve client public
            key certificates. If set to None, then Curve encryption and/or
            authentcation is not enabled. Defaults to auth.CURVE_ALLOW_ANY,
            which allows any client to authenticate. Requires broker_secret_key
            to be set.
        prune_frequency: Frequency (in seconds) at which the broker prunes
            dead workers. Defaults to 5 seconds.
        prune_delta: Delta (in seconds) that must pass since a worker last
            checked in before it is considered dead and is pruned. Defaults to
            10 seconds.
    """
    def __init__(self, daemon_cfg):
        super().__init__()
        self.network_cfg = daemon_cfg.get("network", {})
        self.broker_cfg = daemon_cfg.get("broker", {})
        self.curve_authenticator = None
        self.worker_pool = collections.OrderedDict()

    @property
    def request_socket_port(self):
        request_socket_port = self.network_cfg.get("request_socket_port", 5558)
        return request_socket_port

    @property
    def task_socket_port(self):
        task_socket_port = self.network_cfg.get("task_socket_port", 5559)
        return task_socket_port

    @property
    def poller_timeout(self):
        poller_timeout = self.broker_cfg.get("poller_timeout", 1000)
        return poller_timeout

    @property
    def broker_secret_key(self):
        broker_secret_key = self.broker_cfg.get("broker_secret_key", None)
        return broker_secret_key

    @property
    def client_public_keys(self):
        client_public_keys = self.broker_cfg.get("client_public_keys",
                                                 auth.CURVE_ALLOW_ANY)
        return client_public_keys

    @property
    def prune_frequency(self):
        prune_frequency = self.broker_cfg.get("prune_frequency", 5)
        return prune_frequency

    @property
    def prune_delta(self):
        prune_delta = self.broker_cfg.get("prune_delta", 10)
        return prune_delta

    def run(self):
        """Defines main broker process.

        By default, the broker is designed to setup ZMQ sockets for clients
        and workers, poll for messages from clients and/or workers, and
        distribute client file requests as file tasks to workers. Clients
        only send file requests to the broker. Workers only send status
        messages to the broker (`\x00` means "worker is alive and ready for
        new tasks", `\x10` means "worker is dead/shutdown"). Dead workers are
        pruned from the worker pool on a defined schedule.

        This method can be overriden to create custom brokers.
        """
        logging.info(f"{self.name}: starting up")
        signal.signal(signal.SIGUSR1,
                      functools.partial(utils.shutdown_handler, self))
        self.setup_zmq()
        self.set_prune_at()

        try:
            while 1:
                logging.debug(f"{self.name}: available worker count:"
                              f" {len(self.worker_pool.keys())}")

                if self.worker_pool:
                    sockets = dict(self.client_worker_poller.poll(self.poller_timeout))
                else:
                    sockets = dict(self.worker_poller.poll(self.poller_timeout))

                if sockets.get(self.request_socket) == zmq.POLLIN:
                    msg = self.request_socket.recv_multipart()
                    worker_identity = self.worker_pool.popitem(last=False)[0]
                    self.task_socket.send_multipart([worker_identity, b"",
                                                     worker_identity, b""]
                                                    + msg)

                if sockets.get(self.task_socket) == zmq.POLLIN:
                    msg = self.task_socket.recv_multipart()
                    worker_identity = msg[0]
                    worker_status = msg[2]

                    if worker_status == b"\x00":
                        self.worker_pool[worker_identity] = time.time()
                    elif worker_status == b"\x10":
                        if worker_identity in self.worker_pool:
                            del self.worker_pool[worker_identity]
                self.prune_workers()

        except errors.QuitBroker:
            logging.debug(f"{self.name}: received shutdown signal")
        except Exception:
            logging.exception(f"{self.name}: exception in main loop"
                              " (see traceback below)")
        logging.info(f"{self.name}: shutdown")

    def shutdown(self):
        """Defines broker shutdown."""
        logging.debug(f"{self.name}: shutdown handler received")
        if self.curve_authenticator is not None:
            self.curve_authenticator.stop()
        raise errors.QuitBroker()

    def prune_workers(self):
        """Prunes dead workers from pool.

        This method prunes dead workers from the worker pool. A dead worker is
        any worker that has not checked in with status `\x00` within the
        prune delta time.
        """
        prune_time = time.time()
        if prune_time >= self.prune_at:
            logging.debug(f"{self.name}: beginning prune")
            for (key, value) in dict(self.worker_pool).items():
                if (self.prune_at - value) >= self.prune_delta:
                    del self.worker_pool[key]
                    logging.debug(f"{self.name}: pruned worker"
                                  f" {key.decode()}")
            self.set_prune_at()

    def set_prune_at(self):
        """Updates the prune workers schedule."""
        self.prune_at = time.time() + self.prune_frequency

    def setup_zmq(self):
        """Establishes ZMQ sockets and pollers.

        This method creates ZMQ sockets for clients and workers to connect to
        and creates ZMQ pollers for the broker to read client and worker
        messages on. The client socket uses PUSH/PULL for uni-directional
        communication and the worker socket uses ROUTER/DEALER for
        bi-directional communication. Curve encryption and authentication
        is enabled here.
        """
        context = zmq.Context()
        if self.broker_secret_key and self.client_public_keys:
            self.curve_authenticator = thread.ThreadAuthenticator(context)
            self.curve_authenticator.start()
            self.curve_authenticator.configure_curve(domain="*",
                                                     location=self.client_public_keys)

        self.task_socket = context.socket(zmq.ROUTER)
        self.task_socket.identity = b"broker_self.task_socket"
        self.task_socket.bind(f"tcp://*:{self.task_socket_port}")
        self.worker_poller = zmq.Poller()
        self.worker_poller.register(self.task_socket, zmq.POLLIN)

        self.request_socket = context.socket(zmq.PULL)
        self.request_socket.identity = b"broker_self.request_socket"
        if self.curve_authenticator is not None:
            (server_public,
             server_secret) = auth.load_certificate(self.broker_secret_key)
            self.request_socket.curve_secretkey = server_secret
            self.request_socket.curve_publickey = server_public
            self.request_socket.curve_server = True  # must come before bind
            logging.info(f"{self.name}: Curve enabled")

        self.request_socket.bind(f"tcp://*:{self.request_socket_port}")
        self.client_worker_poller = zmq.Poller()
        self.client_worker_poller.register(self.request_socket, zmq.POLLIN)
        self.client_worker_poller.register(self.task_socket, zmq.POLLIN)


class LogRotate(multiprocessing.Process):
    """Defines a Strelka log rotation process.

    Log rotation processes can be used on worker servers to compress and
    delete Strelka scan result logs.

    Attributes:
        daemon_cfg: Dictionary containing the parsed "daemon" section
            from strelka.yml.
        logrotate_cfg: Dictionary containing the parsed "logrotate"
            sub-section from strelka.yml.
        directory: Directory to run log rotation on. Defaults to
            /var/log/strelka/.
        compression_delta: Delta (in minutes) that must pass since a log file
            was last modified before it is compressed. Defaults to 15 minutes.
        deletion_delta: Delta (in minutes) that must pass since a compressed
            log file was last modified before it is deleted. Defaults to
            360 minutes / 6 hours.
    """
    def __init__(self, daemon_cfg):
        super().__init__()
        self.logrotate_cfg = daemon_cfg.get("logrotate", {})

    @property
    def directory(self):
        directory = self.logrotate_cfg.get("directory", "/var/log/strelka/")
        return directory

    @property
    def compression_delta(self):
        compression_delta = self.logrotate_cfg.get("compression_delta", 15)
        return compression_delta * 60

    @property
    def deletion_delta(self):
        deletion_delta = self.logrotate_cfg.get("deletion_delta", 6 * 60)
        return deletion_delta * 60

    def run(self):
        """Defines main log rotation process.

        By default, log rotation is designed to gzip compress scan result
        log files.

        This method can be overriden to create custom log rotation processes.
        """
        logging.info(f"{self.name}: starting up")
        signal.signal(signal.SIGUSR1,
                      functools.partial(utils.shutdown_handler, self))

        try:
            schedule.every(30).seconds.do(self.gzip_rotate,
                                          self.directory,
                                          self.compression_delta,
                                          self.deletion_delta)

            while 1:
                schedule.run_pending()
                time.sleep(1)

        except errors.QuitLogRotate:
            logging.debug(f"{self.name}: received shutdown signal")
        except Exception:
            logging.exception(f"{self.name}: exception in main loop"
                              " (see traceback below)")
        logging.info(f"{self.name}: shutdown")

    def shutdown(self):
        """Defines log rotation shutdown."""
        logging.debug(f"{self.name}: shutdown handler received")
        raise errors.QuitLogRotate()

    def gzip_rotate(self, directory, compression_delta, deletion_delta):
        """Rotates and deletes files.

        This method performs scan result log compression (gzip) and deletion
        based on user-defined deltas.
        """
        current_time = time.time()
        with os.scandir(directory) as sd:
            for entry in sd:
                if not entry.name.startswith(".") and entry.is_file():
                    file = os.path.join(directory, entry.name)
                    file_mod_time = os.path.getmtime(file)
                    file_delta = current_time - file_mod_time
                    if file.endswith(".gz"):
                        if file_delta >= deletion_delta:
                            os.remove(file)
                            logging.debug(f"{self.name}: deleted file {file}")
                    else:
                        if file_delta >= compression_delta:
                            with open(file, "rb") as log_in:
                                with gzip.open(f"{file}.gz", "wb") as gz_out:
                                    shutil.copyfileobj(log_in, gz_out)
                            os.remove(file)
                            logging.debug(f"{self.name}: compressed"
                                          f" file {file}")


class Worker(multiprocessing.Process):
    """Defines a Strelka worker.

    Workers process file tasks assigned by brokers. All settings are derived
    from the strelka.yml configuration file.

    Attributes:
        strelka_cfg: Path to the strelka.yml file.
        daemon_cfg: Dictionary containing the parsed "daemon" section
            from strelka.yml.
        network_cfg: Dictionary containing the parsed "network" sub-section
            from strelka.yml.
        workers_cfg: Dictionary containing the parsed "workers" sub-section
            from strelka.yml.
        identity: Identity of the worker. Used as the ZMQ routing address
            and log filename.
        server: Hostname of the server running the worker process.
        broker: Network address of the broker. Defaults to 127.0.0.1.
        task_socket_port: Network port that workers receive file tasks over.
            Defaults to 5559.
        task_socket_reconnect: Amount of time (in milliseconds) that the task
            socket will attempt to reconnect in the event of TCP disconnection.
            This will have additional jitter applied (0-100ms).
            Defaults to 100ms (plus jitter).
        task_socket_reconnect_max: Maximum amount of time (in milliseconds)
            that the task socket will attempt to reconnect in the event of TCP
            disconnection. This will have additional jitter applied (0-1000ms).
            Defaults to 4000ms (plus jitter).
        poller_timeout: Amount of time (in milliseconds) that workers poll
            for tasks. Defaults to 1000 milliseconds.
        file_max: Number of files a worker will process before shutting down.
            Defaults to 10000.
        time_to_live: Amount of time (in minutes) that a worker will run
            before shutting down. Defaults to 30 minutes.
        heartbeat_frequency: Frequency (in seconds) at which a worker sends a
            heartbeat to the broker if it has not received any file tasks.
            Defaults to 10 seconds.
        log_file: Location where worker scan results are logged to. Defaults
            to /var/log/strelka/<identity>.log.
        log_field_case: Field case ("camel" or "snake") of the scan result log
            file data. Defaults to camel.
        log_bundle_events: Boolean that determines if scan results should be
            bundled in single event as an array or in multiple events.
            Defaults to True.
    """
    def __init__(self, strelka_cfg, daemon_cfg):
        super().__init__()
        self.strelka_cfg = strelka_cfg
        self.network_cfg = daemon_cfg.get("network", {})
        self.workers_cfg = daemon_cfg.get("workers", {})
        self.identity = b"%05X-%05X" % (random.randint(0, 0x100000),
                                        random.randint(0, 0x100000))
        self.server = socket.gethostname()

    @property
    def broker(self):
        return self.network_cfg.get("broker", "127.0.0.1")

    @property
    def task_socket_port(self):
        return self.network_cfg.get("task_socket_port", 5559)

    @property
    def task_socket_reconnect(self):
        return self.network_cfg.get("task_socket_reconnect", 100 + random.randint(0, 100))

    @property
    def task_socket_reconnect_max(self):
        return self.network_cfg.get("task_socket_reconnect_max", 4000 + random.randint(0, 1000))

    @property
    def poller_timeout(self):
        return self.workers_cfg.get("poller_timeout", 1000)

    @property
    def file_max(self):
        return self.workers_cfg.get("file_max", 10000)

    @property
    def time_to_live(self):
        return self.workers_cfg.get("time_to_live", 30) * 60

    @property
    def heartbeat_frequency(self):
        return self.workers_cfg.get("heartbeat_frequency", 10)

    @property
    def log_file(self):
        log_directory = self.workers_cfg.get("log_directory",
                                             "/var/log/strelka/")
        return os.path.join(log_directory, f"{self.identity.decode()}.log")

    @property
    def log_field_case(self):
        return self.workers_cfg.get("log_field_case", "camel")

    @property
    def log_bundle_events(self):
        return self.workers_cfg.get("log_bundle_events", True)

    def run(self):
        """Defines main worker process.

        By default, the worker is designed to poll for file tasks from the
        broker, distribute the files to scanners, and write the scan results
        to disk. The worker self-manages its life based on how long it has
        lived and how many files it has scanned; on planned or unplanned
        shutdown, the worker notifies the broker it should no longer receive
        file tasks (status `\x10`). If the worker does not receive a file task
        within the configured delta, then it will send a heartbeat to the
        broker notifying it that the worker is still alive and ready to
        receive tasks (`\x00`).

        This method can be overriden to create custom workers.
        """
        logging.info(f"{self.name} ({self.identity.decode()}): starting up")
        signal.signal(signal.SIGUSR1,
                      functools.partial(utils.shutdown_handler, self))
        conf.parse_yaml(path=self.strelka_cfg, section="remote")
        conf.parse_yaml(path=self.strelka_cfg, section="scan")
        self.setup_zmq()

        try:
            counter = 0
            worker_start_time = time.time()
            worker_expire_time = worker_start_time + random.randint(1, 60)
            self.send_ready_status()
            logging.debug(f"{self.name} ({self.identity.decode()}):"
                          " sent ready status")
            self.set_heartbeat_at()

            while 1:
                if counter >= self.file_max:
                    break
                if (time.time() - worker_expire_time) >= self.time_to_live:
                    break

                tasks = dict(self.task_poller.poll(self.poller_timeout))
                if tasks.get(self.task_socket) == zmq.POLLIN:
                    task = self.task_socket.recv_multipart()
                    worker_identity = task[1]
                    if worker_identity != self.identity:
                        logging.error(f"{self.name}"
                                      f" ({self.identity.decode()}): routing"
                                      " error, received task destined for"
                                      f" {worker_identity.decode()}")

                    if len(task) == 4:
                        file_task = task[-1]
                        scan_result = self.distribute_task(file_task)
                        self.log_to_disk(scan_result)
                        counter += 1
                    else:
                        logging.error(f"{self.name}"
                                      f" ({self.identity.decode()}): received"
                                      " invalid task")

                    self.send_ready_status()
                    logging.debug(f"{self.name} ({self.identity.decode()}):"
                                  " sent ready status")
                    self.set_heartbeat_at()

                elif time.time() >= self.heartbeat_at:
                    self.send_ready_status()
                    logging.debug(f"{self.name} ({self.identity.decode()}):"
                                  " sent heartbeat")
                    self.set_heartbeat_at()

        except errors.QuitWorker:
            logging.debug(f"{self.name} ({self.identity.decode()}): received"
                          " shutdown signal")
        except Exception:
            logging.exception(f"{self.name} ({self.identity.decode()}):"
                              " exception in main loop (see traceback below)")

        self.send_shutdown_status()
        logging.debug(f"{self.name} ({self.identity.decode()}): sent"
                      " shutdown status")
        time.sleep(1)
        distribution.close_scanners()
        logging.info(f"{self.name} ({self.identity.decode()}): shutdown"
                     f" after scanning {counter} file(s) and"
                     f" {time.time() - worker_start_time} seconds")

    def shutdown(self):
        """Defines worker shutdown."""
        logging.debug(f"{self.name} ({self.identity.decode()}): shutdown"
                      " handler received")
        raise errors.QuitWorker()

    def setup_zmq(self):
        """Establishes ZMQ socket and poller.

        This method creates a ZMQ socket that connects to the broker and
        creates a ZMQ poller to read broker messages on. The DEALER socket
        will automatically reconnect to the broker in case of disconnection.
        """
        logging.debug(f"{self.name} ({self.identity.decode()}): connecting"
                      " to broker")
        context = zmq.Context()
        self.task_socket = context.socket(zmq.DEALER)
        self.task_socket.setsockopt(zmq.IDENTITY, self.identity)
        self.task_socket.setsockopt(zmq.RECONNECT_IVL, self.task_socket_reconnect)
        self.task_socket.setsockopt(zmq.RECONNECT_IVL_MAX, self.task_socket_reconnect_max)
        self.task_socket.connect(f"tcp://{self.broker}:{self.task_socket_port}")
        self.task_poller = zmq.Poller()
        self.task_poller.register(self.task_socket, zmq.POLLIN)

    def set_heartbeat_at(self):
        """Updates the heartbeat schedule."""
        self.heartbeat_at = time.time() + self.heartbeat_frequency

    def send_reply(self, reply):
        """Sends statuses to the broker.

        Args:
            reply: Message to send to the broker.
        """
        tracker = self.task_socket.send_multipart(reply,
                                                  copy=False,
                                                  track=True)
        while not tracker.done:
            time.sleep(0.1)

    def send_ready_status(self):
        """Sends ready status to the broker."""
        self.send_reply([b"", b"\x00"])

    def send_shutdown_status(self):
        """Sends shutdown status to the broker."""
        self.send_reply([b"", b"\x10"])

    def distribute_task(self, file_task):
        """Distributes file task and returns scan result.

        This method distributes a file task to scanners and returns the scan
        result. Logging is selectively disabled and enabled to ignore log
        messages from packages used by the scanners. Scan results are
        initialized with a variety of default fields.

        Args:
            file_task: File task sent by the broker.
        """
        file_object = objects.protobuf_to_file_object(file_task)
        scan_start_time = datetime.utcnow()
        scan_start_time_iso = scan_start_time.isoformat(timespec="seconds")
        scan_result = {"startTime": scan_start_time_iso,
                       "finishTime": None,
                       "elapsedTime": None,
                       "server": self.server,
                       "worker": self.identity.decode(),
                       "results": []}
        distribution.distribute(file_object, scan_result)
        scan_finish_time = datetime.utcnow()
        scan_finish_time_iso = scan_finish_time.isoformat(timespec="seconds")
        scan_result["finishTime"] = scan_finish_time_iso
        scan_elapsed_time = (scan_finish_time - scan_start_time).total_seconds()
        scan_result["elapsedTime"] = scan_elapsed_time
        return scan_result

    def log_to_disk(self, scan_result):
        """Logs scan result to disk.

        Args:
            scan_result: Scan result to log to disk.
        """
        with open(self.log_file, "a") as log_file:
            if self.log_bundle_events:
                bundled_event = self.format_bundled_event(scan_result)
                log_file.write(f"{bundled_event}\n")
            else:
                for event in self.format_nonbundled_events(scan_result):
                    log_file.write(f"{event}\n")

    def remap_scan_result(self, scan_result):
        """Remaps scan result.

        This method takes a scan result and returns the scan result with
        empty values (strings, lists, and dictionaries) removed and the keys
        formatted according to log_field_case.

        Args:
            scan_result: Scan result to be remapped and formatted.

        Returns:
            Remapped and formatted scan result.
        """
        empty_lambda = lambda p, k, v: v != "" and v != [] and v != {}

        def snake(path, key, value):
            if not isinstance(key, int):
                return (inflection.underscore(key), value)
            return (key, value)

        if self.log_field_case == "snake":
            remapped = iterutils.remap(scan_result, empty_lambda)
            return iterutils.remap(remapped, visit=snake)
        return iterutils.remap(scan_result, empty_lambda)

    def format_nonbundled_events(self, scan_result):
        """Formats scan result as nonbundled, JSON events.

        This method takes a scan result and formats it as a generator of
        individual JSON entries.

        Args:
            scan_result: Scan result to format.

        Yields:
            JSON formatted scan result entries.
        """
        results = scan_result.pop("results")
        individual_result = scan_result
        for result in results:
            yield json.dumps(self.remap_scan_result({**individual_result,
                                                     **result}))

    def format_bundled_event(self, scan_result):
        """Formats scan result as JSON event.

        This method takes a scan result and formats it as a JSON entry.

        Args:
            scan_result: Scan result to format.

        Returns:
            JSON formatted scan result entry.
        """
        return json.dumps(self.remap_scan_result(scan_result))
