#!/usr/bin/env python3
import argparse
from concurrent import futures
import json
import logging
import logging.config
import multiprocessing
import os
import signal
import sys
import time
import uuid
import yaml

import grpc

from etc import conf
from server import lib
import strelka_pb2
import strelka_pb2_grpc

DEFAULTS = {
    'addresses': ['[::]:8443'],
    'strelka_cfg': '/etc/strelka/strelka.yml',
    'logging_cfg': '/etc/strelka/logging.yml',
    'scan_cfg': '/etc/strelka/scan.yml',
    'scan_reload': 900,
    'bundle_events': True,
    'directory': '/var/log/strelka/',
    'field_case': 'camel',
}

run = 1


class StrelkaWrapper(multiprocessing.Process):
    def __init__(self, address):
        super().__init__()
        self.address = address

    def run(self):
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
        servicer = StrelkaServicer()
        strelka_pb2_grpc.add_StrelkaServicer_to_server(servicer, server)
        server.add_insecure_port(self.address)
        server.start()
        while 1:
            time.sleep(1)


class StrelkaServicer(strelka_pb2_grpc.StrelkaServicer):
    def __init__(self):
        self.server_id = str(uuid.uuid4()).upper()[:8]
        self.log_file = os.path.join(conf.strelka_cfg.get('directory',
                                                          DEFAULTS['directory']),
                                     f'{self.server_id}.log')
        self.field_case = conf.strelka_cfg.get('field_case',
                                               DEFAULTS['field_case'])
        self.bundle_events = conf.strelka_cfg.get('bundle_events',
                                                  DEFAULTS['bundle_events'])
        self.logger = logging.getLogger('strelka.log_scan')
        self.logger.propagate = False
        handler = logging.handlers.WatchedFileHandler(self.log_file, delay=True)
        self.logger.addHandler(handler)
        logging.debug(f'Server {self.server_id}: initialized')

    def StreamFile(self, request_iterator, context):
        """Handles streamed gRPC file requests."""
        init_time = time.time()

        self.load_cfg()
        file_object = lib.StrelkaFile()

        log_scan = False
        for request in request_iterator:
            if request.data:
                file_object.append_data(request.data)
            if request.filename:
                file_object.update_filename(request.filename)
            if request.source:
                file_object.update_source(request.source)
            if request.flavors:
                file_object.update_ext_flavors([flavor
                                                for flavor in request.flavors])
            if request.metadata:
                file_object.update_ext_metadata({key: value
                                                for (key, value) in request.metadata.items()})
            if request.log_scan:
                log_scan = request.log_scan

        scan_result = lib.init_scan_result()
        lib.distribute(file_object, scan_result, context)
        scan_result = lib.fin_scan_result(scan_result)
        remapped_scan_result = lib.remap_scan_result(scan_result,
                                                     self.field_case)

        if log_scan:
            if self.bundle_events:
                self.logger.info(json.dumps(remapped_scan_result))
            else:
                for event in lib.split_scan_result(remapped_scan_result.copy()):
                    self.logger.info(json.dumps(event))

        fin_time = time.time() - init_time
        return strelka_pb2.Response(elapsed=fin_time,
                                    result=json.dumps(remapped_scan_result))

    def SendFile(self, request, context):
        """Handles unary gRPC file requests."""
        init_time = time.time()

        self.load_cfg()
        file_object = lib.StrelkaFile(data=request.data)

        log_scan = False
        if request.filename:
            file_object.update_filename(request.filename)
        if request.source:
            file_object.update_source(request.source)
        if request.flavors:
            file_object.update_ext_flavors([flavor
                                            for flavor in request.flavors])
        if request.metadata:
            file_object.update_ext_metadata({key: value
                                            for (key, value) in request.metadata.items()})
        if request.log_scan:
            log_scan = request.log_scan

        scan_result = lib.init_scan_result()
        lib.distribute(file_object, scan_result, context)
        scan_result = lib.fin_scan_result(scan_result)
        remapped_scan_result = lib.remap_scan_result(scan_result,
                                                     self.field_case)

        if log_scan:
            if self.bundle_events:
                self.logger.info(json.dumps(remapped_scan_result))
            else:
                for event in lib.split_scan_result(remapped_scan_result.copy()):
                    self.logger.info(json.dumps(event))

        fin_time = time.time() - init_time
        return strelka_pb2.Response(elapsed=fin_time,
                                    result=json.dumps(remapped_scan_result))

    def load_cfg(self):
        if not conf.scan_cfg or self.reload <= time.time():
            lib.reset_server()
            conf.load_scan(conf.strelka_cfg.get('scan_cfg',
                                                DEFAULTS['scan_cfg']))
            self.reload = time.time() + conf.strelka_cfg.get('scan_reload',
                                                             DEFAULTS['scan_reload'])
            logging.debug(f'Server {self.server_id}: scan settings loaded')


def main():
    def shutdown(signum, frame):
        global run
        run = 0

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    parser = argparse.ArgumentParser(prog='strelka.py',
                                     description='runs Strelka server',
                                     usage='%(prog)s [options]')
    parser.add_argument('-c', '--strelka-config',
                        action='store',
                        dest='strelka_cfg',
                        help='path to strelka configuration file')
    args = parser.parse_args()

    strelka_cfg = ''
    if args.strelka_cfg:
        if not os.path.exists(args.strelka_cfg):
            sys.exit(f'strelka configuration {args.strelka_cfg} does not exist')
        strelka_cfg = args.strelka_cfg
    elif os.path.exists(DEFAULTS['strelka_cfg']):
        strelka_cfg = DEFAULTS['strelka_cfg']

    if not strelka_cfg:
        sys.exit('no strelka configuration found')
    conf.load_strelka(strelka_cfg)

    logging_cfg = conf.strelka_cfg.get('logging_cfg', DEFAULTS['logging_cfg'])
    with open(logging_cfg, 'r') as f:
        logging.config.dictConfig(yaml.safe_load(f.read()))
    logging.info(f'using strelka configuration {strelka_cfg}')

    proc_map = {}
    addresses = conf.strelka_cfg.get('addresses', DEFAULTS['addresses'])
    for addr in addresses:
        new_proc = StrelkaWrapper(addr)
        new_proc.start()
        proc_map[addr] = new_proc

    while run:
        for (addr, proc) in list(proc_map.items()):
            if not proc.is_alive():
                proc.join()
                del proc_map[addr]
                new_proc = StrelkaWrapper(addr)
                new_proc.start()
                proc_map[addr] = new_proc
        time.sleep(5)

    logging.info('shutting down')
    for (addr, proc) in proc_map.items():
        if proc.is_alive():
            os.kill(proc.pid, signal.SIGKILL)
        proc.join()


if __name__ == '__main__':
    main()
