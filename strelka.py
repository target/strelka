#!/usr/bin/env python3
import argparse
from concurrent import futures
import logging
import logging.config
from logging.handlers import RotatingFileHandler
import os
import signal
import socket
import sys
import time

import grpc

from etc import conf
from server import lib
import strelka_pb2
import strelka_pb2_grpc

run = 1

DEFAULT_CONFIGS = {
    'dev_strelka_cfg': 'etc/strelka.yml',
    'sys_strelka_cfg': '/etc/strelka/strelka.yml',
    'dev_logging_ini': 'etc/pylogging.ini',
    'sys_logging_ini': '/etc/strelka/pylogging.ini'
}


class StrelkaServicer(strelka_pb2_grpc.StrelkaServicer):
    def __init__(self):
        conf.load_scan(conf.strelka_cfg.get('scan_cfg'))
        self.reload_scan = time.time() + conf.strelka_cfg.get('refresh')
        self.log_file = os.path.join(conf.strelka_cfg.get('log_directory'), 'strelka.log')
        self.field_case = conf.strelka_cfg.get('log_field_case')
        self.bundle_events = conf.strelka_cfg.get('log_bundle_events')
        self.server = socket.gethostname()
        self.logger = logging.getLogger('Strelka log')
        self.logger.propagate = False
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(self.log_file,
                                      maxBytes=conf.strelka_cfg.get('log_size'),
                                      backupCount=5)
        self.logger.addHandler(handler)

    def StreamFile(self, request_iterator, context):
        '''Handles streamed gRPC file requests.'''
        self.refresh_scan_cfg()

        req_time = time.time()
        file_object = lib.StrelkaFile()
        for request in request_iterator:
            if request.data:
                file_object.append_data(request.data)
            if request.filename:
                file_object.update_filename(request.filename)
            if request.source:
                file_object.update_filename(request.source)
            if request.flavors:
                file_object.update_ext_flavors([flavor for flavor in request.flavors])
            if request.metadata:
                file_object.update_ext_metadata({key: value for (key, value) in request.metadata.items()})

        scan_result = lib.init_scan_result(self.server)
        lib.distribute(file_object, scan_result, context)
        scan_result = lib.finish_scan_result(scan_result)
        formatted_event = lib.format_bundled_event(scan_result,
                                                   'camel')
        self.logger.info(formatted_event)

        fin_time = time.time() - req_time
        return strelka_pb2.Response(elapsed=fin_time)

    def SendFile(self, request, context):
        '''Handles unary gRPC file requests.'''
        self.refresh_scan_cfg()

        req_time = time.time()
        file_object = lib.StrelkaFile(request.data)
        if request.filename:
            file_object.update_filename(request.filename)
        if request.source:
            file_object.update_filename(request.source)
        if request.flavors:
            file_object.update_ext_flavors([flavor for flavor in request.flavors])
        if request.metadata:
            file_object.update_ext_metadata({key: value for (key, value) in request.metadata.items()})

        scan_result = lib.init_scan_result(self.server)
        lib.distribute(file_object, scan_result, context)
        scan_result = lib.finish_scan_result(scan_result)
        formatted_event = lib.format_bundled_event(scan_result,
                                                   'camel')
        self.logger.info(formatted_event)

        fin_time = time.time() - req_time
        return strelka_pb2.Response(elapsed=fin_time)

    def refresh_scan_cfg(self):
        if self.reload_scan <= time.time():
            lib.close_server()
            conf.load_scan(conf.strelka_cfg.get('scan_cfg'))
            self.reload_scan = time.time() + conf.strelka_cfg.get('refresh')


def main():
    def shutdown(signum, frame):
        '''Signal handler for shutting down main.'''
        logging.debug('shutdown triggered')
        global run
        run = 0

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    parser = argparse.ArgumentParser(prog='strelka_grpc.py',
                                     description='runs Strelka via gRPC.',
                                     usage='%(prog)s [options]')
    parser.add_argument('-d', '--debug',
                        action='store_true',
                        default=False,
                        dest='debug',
                        help='enable debug messages to the console')
    parser.add_argument('-c', '--strelka-config',
                        action='store',
                        dest='strelka_cfg',
                        help='path to strelka configuration file')
    parser.add_argument('-l', '--logging-ini',
                        action='store',
                        dest='logging_ini',
                        help='path to python logging configuration file')
    args = parser.parse_args()

    logging_ini = None
    if args.logging_ini:
        if not os.path.exists(args.logging_ini):
            sys.exit(f'logging configuration {args.logging_ini} does not exist')
        logging_ini = args.logging_ini
    elif os.path.exists(DEFAULT_CONFIGS['sys_logging_ini']):
        logging_ini = DEFAULT_CONFIGS['sys_logging_ini']
    elif os.path.exists(DEFAULT_CONFIGS['dev_logging_ini']):
        logging_ini = DEFAULT_CONFIGS['dev_logging_ini']

    if logging_ini is None:
        sys.exit('no logging configuration found')
    logging.config.fileConfig(logging_ini)

    strelka_cfg = None
    if args.strelka_cfg:
        if not os.path.exists(args.strelka_cfg):
            sys.exit(f'strelka configuration {args.strelka_cfg} does not exist')
        strelka_cfg = args.strelka_cfg
    elif os.path.exists(DEFAULT_CONFIGS['sys_strelka_cfg']):
        strelka_cfg = DEFAULT_CONFIGS['sys_strelka_cfg']
    elif os.path.exists(DEFAULT_CONFIGS['dev_strelka_cfg']):
        strelka_cfg = DEFAULT_CONFIGS['dev_strelka_cfg']

    if strelka_cfg is None:
        sys.exit('no strelka configuration found')
    logging.info(f'using strelka configuration {strelka_cfg}')
    conf.load_strelka(strelka_cfg)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    servicer = StrelkaServicer()
    strelka_pb2_grpc.add_StrelkaServicer_to_server(servicer, server)
    server.add_insecure_port(conf.strelka_cfg.get('address'))
    server.start()
    while run:
        time.sleep(5)
    server.stop(0)


if __name__ == '__main__':
    main()
