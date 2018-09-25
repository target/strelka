#!/usr/bin/env python3
"""
strelka_dirstream.py

Command line utility for sending files from a directory to a Strelka cluster
in near real-time. For select source applications (e.g. Bro), this utility
supports parsing metadata embedded in the filename.

If used on a Bro network sensor, then this utility should be paired with the
Bro script `etc/bro/extract-strelka.bro`
"""

import argparse
import functools
import logging
import multiprocessing
import os
import signal
import socket
import sys
import time

import inotify_simple
import interruptingcow

from client import lib
from shared import conf
from shared import errors
from shared import utils


class Worker(multiprocessing.Process):
    """Class that defines file senders.

    Attributes:
        intake_queue: Queue which holds file paths to be processed.
        hostname: Hostname of the server dirstream is running on.
        broker: Network address plus network port of the broker
            (e.g. "127.0.0.1:5558").
        timeout: Amount of time (in seconds) to wait for a file to be
            successfully sent to the broker.
        use_green: Boolean that determines if PyZMQ green should be used.
            This can increase performance at the risk of message loss.
        broker_public_key: Location of the broker Curve public key
            certificate. If set to None, then Curve encryption is not enabled.
            Defaults to None. Must be enabled if the broker is confgured to
            use Curve encryption.
        client_secret_key: Location of the client Curve secret key
            certificate. If set to None, then Curve encryption is not enabled.
            Defaults to None. Must be enabled if the broker is confgured to
            use Curve encryption.
        source: Application that writes files to the directory, used to
            control metadata parsing functionality.
        meta_separator: Unique string used to separate pieces of metadata in a
            filename, used to parse metadata and send it along with the file
            to the cluster.
        delete_files: Boolean that determines if files should be deleted after
            they are sent to the cluster.
        report_frequency: Frequency (in seconds) at which the worker reports
            how many files it successfully sent.

    Args:
        directory_cfg: Dictionary containing parsed dirstream directory configuration.
        network_cfg: Dictionary containing parsed dirstream network configuration.
    """

    def __init__(self, intake_queue, directory_cfg, network_cfg):
        super().__init__()
        self.hostname = socket.gethostname()
        self.intake_queue = intake_queue
        self.broker = network_cfg.get("broker", "127.0.0.1:5558")
        self.timeout = network_cfg.get("timeout", 10)
        self.use_green = network_cfg.get("use_green", True)
        self.broker_public_key = network_cfg.get("broker_public_key", None)
        self.client_secret_key = network_cfg.get("client_secret_key", None)
        self.source = directory_cfg.get("source", None)
        self.meta_separator = directory_cfg.get("meta_separator", "S^E^P")
        self.delete_files = directory_cfg.get("delete_files", False)
        self.report_frequency = directory_cfg.get("report_frequency", 60)

    def run(self):
        """Defines main dirstream process."""
        logging.info(f"{self.name}: starting up")
        signal.signal(signal.SIGUSR1,
                      functools.partial(utils.shutdown_handler, self))
        client = lib.Client(f"tcp://{self.broker}",
                            use_green=self.use_green,
                            broker_public_key=self.broker_public_key,
                            client_secret_key=self.client_secret_key)
        if self.client_secret_key and self.broker_public_key:
            logging.info(f"{self.name}: initialized connection to"
                         f" {self.broker} using Curve")
        else:
            logging.info(f"{self.name}: initialized connection to"
                         f" {self.broker} using plaintext")

        try:
            self.sent = 0
            self.report_at = time.time() + self.report_frequency

            while 1:
                file_path = self.intake_queue.get()
                filename = file_path.split("/")[-1]
                filename = filename.replace("%2F", "/")

                metadata = {}
                flavors = []
                if (self.source is not None and
                    self.meta_separator in filename):
                    if self.source == "bro":
                        (metadata,
                         flavors) = lib.parse_bro_metadata(filename,
                                                           self.meta_separator)

                try:
                    with open(file_path, "rb") as open_file:
                        file_request = lib.request_to_protobuf(file=open_file.read(),
                                                               filename=filename,
                                                               source=self.hostname,
                                                               flavors=flavors,
                                                               metadata=metadata)
                        result = client.send(file_request,
                                             timeout=self.timeout)
                        if not result:
                            logging.debug(f"{self.name}: failed to send"
                                          f" file {filename}")
                        else:
                            self.sent += 1

                except IOError:
                    logging.error(f"{self.name}: failed to open"
                                  f" file {file_path} (IOError)")

                if self.delete_files:
                    try:
                        os.remove(file_path)

                    except OSError:
                        logging.error(f"{self.name}: failed to delete"
                                      f" file {file_path} (OSError)")
                    except PermissionError:
                        logging.error(f"{self.name}: failed to delete"
                                      f" file {file_path} (PermissionError)")

                self.report_metrics()

        except errors.QuitWorker:
            logging.debug(f"{self.name}: received shutdown signal")

        self.report_metrics()
        client.close()

    def shutdown(self):
        """Defines dirstream shutdown."""
        logging.debug(f"{self.name}: shutdown handler received")
        raise errors.QuitWorker()

    def report_metrics(self):
        """Reports file send metrics."""
        if time.time() >= self.report_at:
            logging.info(f"{self.name}: sent {self.sent} files")
            self.sent = 0
            self.report_at = time.time() + self.report_frequency


run = 1

DEFAULT_CONFIGS = {
    "dev_dirstream_cfg": "etc/dirstream/dirstream.yml",
    "sys_dirstream_cfg": "/etc/strelka/dirstream.yml"
}


def main():
    def shutdown(signum, frame):
        """Signal handler for shutting down main."""
        logging.debug("main: shutdown triggered")
        global run
        run = 0

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    parser = argparse.ArgumentParser(prog="strelka_dirstream.py",
                                     description="sends files from a directory"
                                                 " to a Strelka cluster in"
                                                 " near real-time.",
                                     usage="%(prog)s [options]")
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        default=False,
                        dest="debug",
                        help="enable debug messages to the console")
    parser.add_argument("-c", "--dirstream-config",
                        action="store",
                        dest="dirstream_cfg",
                        help="path to dirstream configuration file")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S")
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S")

    dirstream_cfg = None
    if args.dirstream_cfg:
        if not os.path.exists(args.dirstream_cfg):
            sys.exit(f"main: stream directory config {args.dirstream_cfg}"
                     " does not exist")
        dirstream_cfg = args.dirstream_cfg
    elif os.path.exists(DEFAULT_CONFIGS['sys_dirstream_cfg']):
        dirstream_cfg = DEFAULT_CONFIGS['sys_dirstream_cfg']
    elif os.path.exists(DEFAULT_CONFIGS['dev_dirstream_cfg']):
        dirstream_cfg = DEFAULT_CONFIGS['dev_dirstream_cfg']

    if dirstream_cfg is None:
        sys.exit("main: no dirstream configuration found")
    logging.info(f"main: using dirstream configuration {dirstream_cfg}")

    dirstream_cfg = conf.parse_yaml(path=dirstream_cfg, section="dirstream")
    directory_cfg = dirstream_cfg.get("directory", {})
    network_cfg = dirstream_cfg.get("network", {})
    processes_cfg = dirstream_cfg.get("processes", {})
    directory = directory_cfg.get("directory")
    shutdown_timeout = processes_cfg.get("shutdown_timeout", 10)
    worker_count = processes_cfg.get("worker_count", 1)

    worker_processes = []

    if not os.path.isdir(directory):
        sys.exit(f"main: directory {directory} does not exist")

    manager = multiprocessing.Manager()
    intake_queue = manager.Queue()
    inotify = inotify_simple.INotify()
    watch_flags = inotify_simple.flags.CLOSE_WRITE
    inotify.add_watch(directory, watch_flags)

    for _ in range(worker_count):
        worker_process = Worker(intake_queue, directory_cfg, network_cfg)
        worker_process.start()
        worker_processes.append(worker_process)

    with os.scandir(directory) as sd:
        for entry in sd:
            if not entry.name.startswith(".") and entry.is_file():
                file_path = os.path.join(directory, entry.name)
                intake_queue.put(file_path)

    while run:
        for process in list(worker_processes):
            if not process.is_alive():
                process.join()
                worker_processes.remove(process)
                worker_process = Worker(intake_queue,
                                        directory_cfg,
                                        network_cfg)
                worker_process.start()
                worker_processes.append(worker_process)

        for evt in inotify.read(timeout=100, read_delay=500):
            file_path = os.path.join(directory, evt.name)
            intake_queue.put(file_path)

    logging.info("main: starting shutdown of running child processes"
                 f" (using timeout value {shutdown_timeout})")
    try:
        with interruptingcow.timeout(shutdown_timeout,
                                     exception=errors.QuitDirStream):
            utils.signal_children(worker_processes, signal.SIGUSR1)
            logging.debug("main: finished shutdown of running"
                          " child processes")
    except errors.QuitDirStream:
        logging.debug("main: starting forcible shutdown of running"
                      " child processes")
        utils.signal_children(worker_processes, signal.SIGKILL)
    logging.info("main: finished")


if __name__ == "__main__":
    main()
