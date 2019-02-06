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
import glob
import logging
import multiprocessing
import os
import signal
import socket
import sys
import time

import interruptingcow

from client import lib
from shared import conf
from shared import errors
from shared import utils


class DirWorker(multiprocessing.Process):
    """Class that defines workers that poll a directory and send files to Strelka.

    Attributes:
        directory: Directory to send files from. Defaults to None.
        recursive: Recursively scan directories. Defaults to False.
        source: Application that writes files to the directory, used to
            control metadata parsing functionality.
        meta_separator: Unique string used to separate pieces of metadata in a
            filename, used to parse metadata and send it along with the file
            to the cluster. Defaults to "S^E^P".
        file_mtime_delta; Delta (in seconds) that must pass since a file was
            last modified before it is sent to the cluster. Defaults to 5 seconds.
        delete_files: Boolean that determines if files should be deleted after
            they are sent to the cluster. Defaults to False.
        move_files: Boolean that determines if files should be moved after
            they are sent to the cluster. Defaults to False.
        move_directory: Directory to move files to once they are scanned.
            Defaults to None.
        broker: Network address plus network port of the broker.
            Defaults to "127.0.0.1:5558".
        timeout: Amount of time (in seconds) to wait for a file to be
            successfully sent to the broker. Defaults to 10 seconds.
        use_green: Boolean that determines if PyZMQ green should be used.
            This can increase performance at the risk of message loss.
            Defaults to True.
        broker_public_key: Location of the broker Curve public key
            certificate. If set to None, then Curve encryption is not enabled.
            Defaults to None. Must be enabled if the broker is confgured to
            use Curve encryption.
        client_secret_key: Location of the client Curve secret key
            certificate. If set to None, then Curve encryption is not enabled.
            Defaults to None. Must be enabled if the broker is confgured to
            use Curve encryption.
        hostname: Hostname of the server running dirstream.

     Args:
        worker_cfg: Dictionary containing unparsed dirstream worker configuration.
    """

    def __init__(self, worker_cfg):
        super().__init__()
        directory_cfg = worker_cfg.get("directory", {})
        network_cfg = worker_cfg.get("network", {})
        self.directory = directory_cfg.get("directory", None)
        self.recursive = directory_cfg.get("recursive", False)
        self.source = directory_cfg.get("source", None)
        self.meta_separator = directory_cfg.get("meta_separator", "S^E^P")
        self.file_mtime_delta = directory_cfg.get("file_mtime_delta", 5)
        self.delete_files = directory_cfg.get("delete_files", False)
        self.move_files = directory_cfg.get("move_files", False)
        self.move_directory = directory_cfg.get("move_directory", None)
        self.broker = network_cfg.get("broker", "127.0.0.1:5558")
        self.timeout = network_cfg.get("timeout", 10)
        self.use_green = network_cfg.get("use_green", True)
        self.broker_public_key = network_cfg.get("broker_public_key", None)
        self.client_secret_key = network_cfg.get("client_secret_key", None)
        self.hostname = socket.gethostname()
        self.sent = 0

    def run(self):
        """Defines main dirstream process."""
        logging.info(f"{self.name}: starting up")
        signal.signal(signal.SIGUSR1,
                      functools.partial(utils.shutdown_handler, self))
        self.client = lib.Client(f"tcp://{self.broker}",
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
            while 1:
                current_time = time.time()
                iglobpath = f"{self.directory}/*"
                if self.recursive:
                    iglobpath = f"{self.directory}/**/*"
                globbed_paths = glob.iglob(pathname=iglobpath, recursive=self.recursive)
                for _, entry in enumerate(globbed_paths):
                    if os.path.isfile(entry):
                        file_mtime = os.stat(path=entry).st_mtime
                        mtime_delta = current_time - file_mtime
                        if mtime_delta >= self.file_mtime_delta:
                            self.send_file(entry)
                            if self.delete_files:
                                self.delete_file(entry)
                            if self.move_files:
                                self.move_file(entry)
                            logging.debug(f"{self.name}: Sent file {entry}")
                if self.sent != 0:
                    logging.debug(f"{self.name}: Total files sent: {self.sent}"
                                  f" from {self.directory}")
                self.sent = 0
                time.sleep(1)

        except errors.QuitWorker:
            logging.debug(f"{self.name}: received shutdown signal")

    def shutdown(self):
        """Defines dirstream shutdown."""
        logging.debug(f"{self.name}: shutdown handler received")
        raise errors.QuitWorker()

    def delete_file(self, path):
        """Deletes files."""
        try:
            os.remove(path)

        except OSError:
            logging.error(f"{self.name}: failed to delete"
                          f" file {path} (OSError)")
        except PermissionError:
            logging.error(f"{self.name}: failed to delete"
                          f" file {path} (PermissionError)")

    def move_file(self, path):
        """Moves files."""
        try:
            os.rename(src=path, dst=f"{self.move_directory}/{path.split('/')[-1]}")

        except OSError:
            logging.error(f"{self.name}: failed to move"
                          f" file {path} dest {self.move_directory}/{path.split('/')[-1]} (OSError)")
        except PermissionError:
            logging.error(f"{self.name}: failed to move"
                          f" file {path} (PermissionError)")

    def send_file(self, path):
        """Sends files to configured Strelka cluster."""
        filename = path.split("/")[-1]
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
            with open(path, "rb") as open_file:
                file_request = lib.request_to_protobuf(file=open_file.read(),
                                                       filename=filename,
                                                       source=self.hostname,
                                                       flavors=flavors,
                                                       metadata=metadata)
                result = self.client.send(file_request,
                                          timeout=self.timeout)
                if not result:
                    logging.debug(f"{self.name}: failed to send"
                                  f" file {filename}")
                else:
                    self.sent += 1

        except IOError:
            logging.error(f"{self.name}: failed to open"
                          f" file {path} (IOError)")


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
    processes_cfg = dirstream_cfg.get("processes", {})
    shutdown_timeout = processes_cfg.get("shutdown_timeout", 10)
    workers_cfg = dirstream_cfg.get("workers", [])

    worker_processes = {}

    for worker_cfg in workers_cfg:
        worker_process = DirWorker(worker_cfg)
        worker_process.start()
        worker_processes[worker_process] = worker_cfg

    while run:
        for process in list(worker_processes.keys()):
            if not process.is_alive():
                process.join()
                worker_cfg = worker_processes.pop(process)
                worker_process = DirWorker(worker_cfg)
                worker_process.start()
                worker_processes[worker_process] = worker_cfg
        time.sleep(5)

    logging.info("main: starting shutdown of running child processes"
                 f" (using timeout value {shutdown_timeout})")

    try:
        with interruptingcow.timeout(shutdown_timeout,
                                     exception=errors.QuitDirStream):
            utils.signal_children(list(worker_processes.keys()), signal.SIGUSR1)
            logging.debug("main: finished shutdown of running"
                          " child processes")
    except errors.QuitDirStream:
        logging.debug("main: starting forcible shutdown of running"
                      " child processes")
        utils.signal_children(list(worker_processes.keys()), signal.SIGKILL)
    logging.info("main: finished")


if __name__ == "__main__":
    main()
