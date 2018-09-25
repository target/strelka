#!/usr/bin/env python
"""
generate_curve_certificates.py

Command line utility to create broker and client Curve certificates.
Curve support requires ZMQ version 4.0 and up.
"""

import argparse
import os
import shutil
import sys

import zmq
from zmq import auth


def generate_certificates(base_dir, broker_bool, client_bool, client_file):
    """Generate client and/or broker Curve certificates"""

    keys_dir = os.path.join(base_dir, "tmp_certificates")
    if broker_bool:
        broker_keys_dir = os.path.join(keys_dir, "broker_keys")
    if client_bool:
        client_keys_dir = os.path.join(keys_dir, "client_keys")

    if os.path.exists(keys_dir):
        shutil.rmtree(keys_dir)
    os.mkdir(keys_dir)
    if broker_bool:
        os.mkdir(broker_keys_dir)
    if client_bool:
        os.mkdir(client_keys_dir)

    if broker_bool:
        (broker_public_file,
         broker_secret_file) = auth.create_certificates(broker_keys_dir,
                                                        "broker")
    if client_bool:
        if client_file:
            with open(client_file) as f:
                clients = [line.rstrip("\n") for line in f]

            if clients:
                for client_hostname in clients:
                    (client_public_file,
                     client_secret_file) = auth.create_certificates(client_keys_dir,
                                                                    f"client_{client_hostname}")
            else:
                print(f"No client hostnames found in {client_file}")
                sys.exit()

        else:
            (client_public_file,
             client_secret_file) = auth.create_certificates(client_keys_dir,
                                                            "client")


if __name__ == "__main__":
    if zmq.zmq_version_info() < (4, 0):
        print("Security is not supported in libzmq version < 4.0."
              f" \ncurrent libzmq version is {zmq.zmq_version()}")
        sys.exit()

    parser = argparse.ArgumentParser(prog="generate_curve_certificates.py",
                                     description="generates curve certificates"
                                                 " used by brokers and"
                                                 " clients.",
                                     usage="%(prog)s [options]")
    parser.add_argument("-p", "--path",
                        dest="path",
                        help="path to store keys in (defaults to"
                        " current working directory)")
    parser.add_argument("-b", "--broker",
                        dest="broker_bool",
                        action="store_true",
                        help="generate curve certificates for a broker")
    parser.add_argument("-c", "--client",
                        dest="client_bool",
                        action="store_true",
                        help="generate curve certificates for a client")
    parser.add_argument("-cf", "--client-file",
                        dest="client_file",
                        help="path to a file containing line-separated list"
                             " of clients to generate keys for, useful for"
                             " creating many client keys at once")
    args = parser.parse_args()

    broker_bool = args.broker_bool or False
    client_bool = args.client_bool or False
    path = args.path or os.getcwd()
    client_file = args.client_file or None

    if broker_bool or client_bool:
        generate_certificates(path, broker_bool,
                              client_bool, client_file)
    else:
        print("Please set options to generate keys.")
        sys.exit()
