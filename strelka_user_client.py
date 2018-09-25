#!/usr/bin/env python3
"""
strelka_user_client.py

Command line utility for sending files from a client to a Strelka cluster.
This is intended to be used for ad-hoc file requests and should not be
expected to perform long-lived or fully automated file transfers.
"""

import argparse
import json
import logging
import os
import socket

from client import lib


def send_request(client, path=None, location=None,
                 hostname=None, timeout=None):
    """Sends file requests to a Strelka cluster.

    Args:
        client: Previously configured instance of lib.Client().
        path: Path to the file to send to the cluster.
        location: Dictionary containing values related to the location
            of the remote file to retrieve.
        hostname: Hostname of the client sending the file to the cluster.
        timeout: Amount of time (in seconds) to wait until a file transfer
            times out.
    """
    protobuf_request = None
    if path is not None:
        with open(path, "rb") as fin:
            protobuf_request = lib.request_to_protobuf(file=fin.read(),
                                                       filename=path,
                                                       source=hostname)
    elif location is not None:
        protobuf_request = lib.request_to_protobuf(location=location,
                                                   source=hostname)

    if protobuf_request is not None:
        logging.debug(f"Sending {path or location} with timeout {timeout}")
        result = client.send(protobuf_request, timeout=timeout)

        if result:
            logging.debug(f"Successfully sent {path or location}")
        else:
            logging.debug(f"Failed to send {path or location}")
    else:
        logging.error("No file or location provided!")


def main():
    parser = argparse.ArgumentParser(prog="strelka_user_client.py",
                                     description="sends ad-hoc file requests to"
                                                 " a Strelka cluster.",
                                     usage="%(prog)s [options]")
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        dest="debug",
                        help="enable debug messages to the console")
    parser.add_argument("-b", "--broker", required=True,
                        dest="broker", type=str,
                        help="network address and network port of the broker"
                             " (e.g. 127.0.0.1:5558)")
    parser.add_argument("-p", "--path",
                        dest="path", type=str,
                        help="path to the file or directory of files to send"
                             " to the broker")
    parser.add_argument("-l", "--location",
                        dest="location", type=str,
                        help="JSON representation of a location for the"
                             " cluster to retrieve files from")
    parser.add_argument("-t", "--timeout",
                        dest="timeout", type=int,
                        help="amount of time (in seconds) to wait until a"
                             " file transfer times out")
    parser.add_argument("-bpk", "--broker-public-key",
                        action="store",
                        dest="broker_public_key",
                        help="location of the broker Curve public key"
                             " certificate (this option enables curve"
                             " encryption and must be used if the broker"
                             " has curve enabled)")
    parser.add_argument("-csk", "--client-secret-key",
                        action="store",
                        dest="client_secret_key",
                        help="location of the client Curve secret key"
                             " certificate (this option enables curve"
                             " encryption and must be used if the broker"
                             " has curve enabled)")
    parser.add_argument("-ug", "--use-green",
                        action="store_true",
                        dest="use_green",
                        help="determines if PyZMQ green should be used, which"
                             " can increase performance at the risk of"
                             " message loss")
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

    path = args.path or ""
    location = {}
    if args.location:
        location = json.loads(args.location)
    timeout = args.timeout or 60
    broker_public_key = args.broker_public_key or None
    client_secret_key = args.client_secret_key or None
    use_green = args.use_green
    hostname = socket.gethostname()

    client = lib.Client(f"tcp://{args.broker}", use_green=use_green,
                        broker_public_key=broker_public_key,
                        client_secret_key=client_secret_key)

    if path:
        if os.path.isdir(path):
            with os.scandir(path) as sd:
                for entry in sd:
                    if not entry.name.startswith(".") and entry.is_file():
                        file_path = os.path.join(path, entry.name)
                        send_request(client, path=file_path,
                                     hostname=hostname, timeout=timeout)
        else:
            send_request(client, path=path,
                         hostname=hostname, timeout=timeout)
    elif location:
        send_request(client, location=location,
                     hostname=hostname, timeout=timeout)


if __name__ == "__main__":
    main()
