#!/usr/bin/env python3
"""
strelka.py

Command line utility for running Strelka clusters. Hosts running Strelka
clients (see `strelka/user_client.py` as an example) send files to a
server running a Strelka broker which tasks out files to servers running
Strelka workers. This utility uses the default Broker and Worker classes.
"""
import argparse
import logging
import logging.config
import os
import signal
import sys
import time

import interruptingcow

from server import lib
from shared import conf
from shared import errors
from shared import utils

run = 1

DEFAULT_CONFIGS = {
    "dev_strelka_cfg": "etc/strelka/strelka.yml",
    "sys_strelka_cfg": "/etc/strelka/strelka.yml",
    "dev_logging_ini": "etc/strelka/pylogging.ini",
    "sys_logging_ini": "/etc/strelka/pylogging.ini"
}


def main():
    def shutdown(signum, frame):
        """Signal handler for shutting down main."""
        logging.debug("shutdown triggered")
        global run
        run = 0

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    parser = argparse.ArgumentParser(prog="strelka.py",
                                     description="runs Strelka as a"
                                                 " distributed cluster.",
                                     usage="%(prog)s [options]")
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        default=False,
                        dest="debug",
                        help="enable debug messages to the console")
    parser.add_argument("-c", "--strelka-config",
                        action="store",
                        dest="strelka_cfg",
                        help="path to strelka configuration file")
    parser.add_argument("-l", "--logging-ini",
                        action="store",
                        dest="logging_ini",
                        help="path to python logging configuration file")
    args = parser.parse_args()

    logging_ini = None
    if args.logging_ini:
        if not os.path.exists(args.logging_ini):
            sys.exit(f"logging configuration {args.logging_ini}"
                     " does not exist")
        logging_ini = args.logging_ini
    elif os.path.exists(DEFAULT_CONFIGS["sys_logging_ini"]):
        logging_ini = DEFAULT_CONFIGS["sys_logging_ini"]
    elif os.path.exists(DEFAULT_CONFIGS["dev_logging_ini"]):
        logging_ini = DEFAULT_CONFIGS["dev_logging_ini"]

    if logging_ini is None:
        sys.exit("no logging configuration found")
    logging.config.fileConfig(logging_ini)

    strelka_cfg = None
    if args.strelka_cfg:
        if not os.path.exists(args.strelka_cfg):
            sys.exit(f"strelka configuration {args.strelka_cfg}"
                     " does not exist")
        strelka_cfg = args.strelka_cfg
    elif os.path.exists(DEFAULT_CONFIGS["sys_strelka_cfg"]):
        strelka_cfg = DEFAULT_CONFIGS["sys_strelka_cfg"]
    elif os.path.exists(DEFAULT_CONFIGS["dev_strelka_cfg"]):
        strelka_cfg = DEFAULT_CONFIGS["dev_strelka_cfg"]

    if strelka_cfg is None:
        sys.exit("no strelka configuration found")
    logging.info(f"using strelka configuration {strelka_cfg}")

    daemon_cfg = conf.parse_yaml(path=strelka_cfg, section="daemon")
    processes_cfg = daemon_cfg.get("processes", {})
    run_broker = processes_cfg.get("run_broker", True)
    run_workers = processes_cfg.get("run_workers", True)
    worker_count = processes_cfg.get("worker_count", 4)
    run_logrotate = processes_cfg.get("run_logrotate", True)
    shutdown_timeout = processes_cfg.get("shutdown_timeout", 45)

    broker_process = None
    logrotate_process = None
    worker_processes = []

    if run_broker:
        broker_process = lib.Broker(daemon_cfg)
        broker_process.start()
    else:
        logging.info("broker disabled")

    if run_logrotate:
        logrotate_process = lib.LogRotate(daemon_cfg)
        logrotate_process.start()
    else:
        logging.info("log rotation disabled")

    if run_workers:
        for _ in range(worker_count):
            worker_process = lib.Worker(strelka_cfg, daemon_cfg)
            worker_process.start()
            worker_processes.append(worker_process)
    else:
        logging.info("workers disabled")

    while run:
        if run_broker:
            if not broker_process.is_alive():
                broker_process.join()
                broker_process = lib.Broker(daemon_cfg)
                broker_process.start()

        if run_logrotate:
            if not logrotate_process.is_alive():
                logrotate_process.join()
                logrotate_process = lib.LogRotate(daemon_cfg)
                logrotate_process.start()

        if run_workers:
            for process in list(worker_processes):
                if not process.is_alive():
                    process.join()
                    worker_processes.remove(process)
                    worker_process = lib.Worker(strelka_cfg, daemon_cfg)
                    worker_process.start()
                    worker_processes.append(worker_process)
        time.sleep(5)

    logging.info("starting shutdown of running child processes"
                 f" (using timeout value {shutdown_timeout})")
    try:
        with interruptingcow.timeout(shutdown_timeout,
                                     exception=errors.QuitStrelka):
            if run_broker:
                utils.signal_children([broker_process], signal.SIGUSR1)
            if run_workers:
                utils.signal_children(worker_processes, signal.SIGUSR1)
            if run_logrotate:
                utils.signal_children([logrotate_process], signal.SIGUSR1)
            logging.debug("finished shutdown of running"
                          " child processes")
    except errors.QuitStrelka:
        logging.debug("starting forcible shutdown of running"
                      " child processes")
        if run_broker:
            utils.signal_children([broker_process], signal.SIGKILL)
        if run_workers:
            utils.signal_children(worker_processes, signal.SIGKILL)
        if run_logrotate:
            utils.signal_children([logrotate_process], signal.SIGKILL)
    logging.info("finished")


if __name__ == "__main__":
    main()
