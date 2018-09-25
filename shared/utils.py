"""Defines functions that are used in client- and server-side utilties."""
import logging
import os


def shutdown_handler(process, signum, frame):
    """Runs shutdown on child process.

    This function is wrapped in functools to pass the signal to the child
    process.

    Args:
        process: Process to shutdown.
        signum: Signal passed to process shutdown.
    """
    logging.debug(f"{process.name}: shutdown handler triggered"
                  f" (signal {signum})")
    process.shutdown()


def signal_children(processes, signum):
    """Sends signal to child processes.

    Args:
        processes: Processes to send signal to.
        signum: Signal to send to processes.
    """
    for process in processes:
        if process.is_alive():
            os.kill(process.pid, signum)
        process.join()
        logging.debug(f"{process.name}: shutdown (signal {signum})")
