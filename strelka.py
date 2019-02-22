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
    'strelka_cfg': '/etc/strelka/strelka.yaml',
    'logging_cfg': '/etc/strelka/logging.yaml',
    'scan_cfg': '/etc/strelka/scan.yaml',
    'max_rpcs': None,
    'max_workers': 1,
    'scan_reload': 900,
    'event_log': {},
}

run = 1


class StrelkaWrapper(multiprocessing.Process):
    """Runs Strelka gRPC servicer as a child process."""
    def __init__(self, address, rpcs, workers):
        """Inits Strelka gRPC servicer process.

        Args:
            address: Local address of the gRPC servicer.
                Defaults to '[::]:8443'.
            rpcs: Maximum number of concurrent RPCs to handle.
                Defaults to None (no limit).
            workers: Maximum number of thread workers to allocate for RPCs.
                Defaults to 1.
        """
        super().__init__()
        self.address = address
        self.rpcs = rpcs
        self.workers = workers

    def run(self):
        """Runs Strelka gRPC servicer indefinitely."""
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=self.workers),
                             maximum_concurrent_rpcs=self.rpcs)
        servicer = StrelkaServicer()
        strelka_pb2_grpc.add_StrelkaServicer_to_server(servicer, server)
        server.add_insecure_port(self.address)
        server.start()
        while 1:
            time.sleep(1)


class StrelkaServicer(strelka_pb2_grpc.StrelkaServicer):
    """Defines gRPC services provided by Strelka."""
    def __init__(self):
        """Inits Strelka gRPC servicer.

        StrelkaServicer supports unary Data requests, streamed Data requests, and
        unary Location requests. Clients have the option to request the retrieval
        of file events and the server has the option to log all file events
        to local disk.

        Args:
            server_id: UUID assigned to the server process.
            logger: FileHandler for writing file events to the server.
            bundle: Bundle configuration for events written to the server.
            case: Case configuration for events written to the server.
        """
        self.server_id = str(uuid.uuid4()).upper()[:8]
        self.logger = None
        logging.debug(f'Server {self.server_id}: initialized')

        evt_log = conf.strelka_cfg.get('event_log', DEFAULTS['event_log'])
        if evt_log:
            self.logger = logging.getLogger(self.server_id)
            self.logger.propagate = False
            log_file = os.path.join(evt_log.get('directory',
                                                '/var/log/strelka/'),
                                    f'{self.server_id}.log')
            handler = logging.handlers.WatchedFileHandler(log_file, delay=True)
            self.logger.addHandler(handler)
            self.bundle = evt_log.get('bundle', True)
            self.case = evt_log.get('case', 'camel')

    def StreamData(self, request_iterator, context):
        """Handles streamed gRPC file requests."""
        init_time = time.time()

        self.load_cfg()
        file_object = lib.StrelkaFile()

        cli_req = {}
        cli_bundle = None
        cli_case = None
        for request in request_iterator:
            if request.data:
                file_object.append_data(request.data)
            if request.request:
                cli_req = {'uid': request.request.uid,
                           'client': request.request.client,
                           'source': request.request.source}
            if request.metadata.filename:
                file_object.update_filename(request.metadata.filename)
            if request.metadata.flavors:
                file_object.update_ext_flavors([flavor
                                                for flavor in request.metadata.flavors])
            if request.metadata.metadata:
                file_object.update_ext_metadata({key: value
                                                for (key, value) in request.metadata.metadata.items()})
            if request.retrieve:
                cli_bundle = request.retrieve.bundle
                cli_case = request.retrieve.case

        response = strelka_pb2.Response(uid=cli_req['uid'])
        scan_result = lib.init_scan_result(cli_req)
        lib.distribute(file_object, scan_result, context)
        scan_result = lib.fin_scan_result(scan_result)

        if self.logger is not None:
            srv_evt = lib.result_to_evt(scan_result, self.bundle, self.case)
            if isinstance(srv_evt, list):
                for e in srv_evt:
                    self.logger.info(e)
            else:
                self.logger.info(srv_evt)

        if cli_bundle is not None and cli_case is not None:
            cli_evt = lib.result_to_evt(scan_result, cli_bundle, cli_case)
            if isinstance(cli_evt, list):
                response.events.extend(cli_evt)
            else:
                response.events.append(cli_evt)

        response.elapsed = time.time() - init_time
        return response

    def SendData(self, request, context):
        """Handles unary gRPC file requests."""
        init_time = time.time()

        self.load_cfg()
        file_object = lib.StrelkaFile()

        cli_req = {}
        cli_bundle = None
        cli_case = None
        if request.data:
            file_object.append_data(request.data)
        if request.request:
            cli_req = {'uid': request.request.uid,
                       'client': request.request.client,
                       'source': request.request.source}
        if request.metadata.filename:
            file_object.update_filename(request.metadata.filename)
        if request.metadata.flavors:
            file_object.update_ext_flavors([flavor
                                            for flavor in request.metadata.flavors])
        if request.metadata.metadata:
            file_object.update_ext_metadata({key: value
                                            for (key, value) in request.metadata.metadata.items()})
        if request.retrieve:
            cli_bundle = request.retrieve.bundle
            cli_case = request.retrieve.case

        response = strelka_pb2.Response(uid=cli_req['uid'])
        scan_result = lib.init_scan_result(cli_req)
        lib.distribute(file_object, scan_result, context)
        scan_result = lib.fin_scan_result(scan_result)

        if self.logger is not None:
            srv_evt = lib.result_to_evt(scan_result, self.bundle, self.case)
            if isinstance(srv_evt, list):
                for e in srv_evt:
                    self.logger.info(e)
            else:
                self.logger.info(srv_evt)

        if cli_bundle is not None and cli_case is not None:
            cli_evt = lib.result_to_evt(scan_result, cli_bundle, cli_case)
            if isinstance(cli_evt, list):
                response.events.extend(cli_evt)
            else:
                response.events.append(cli_evt)

        response.elapsed = time.time() - init_time
        return response

    def SendLocation(self, request, context):
        """Handles unary gRPC location requests."""
        init_time = time.time()

        self.load_cfg()
        file_object = lib.StrelkaFile()

        cli_req = {}
        cli_bundle = None
        cli_case = None
        if request.location:
            location = {key:
                        value for (key, value) in request.location.items()}
        if request.request:
            cli_req = {'uid': request.request.uid,
                       'client': request.request.client,
                       'source': request.request.source}
        if request.metadata.filename:
            file_object.update_filename(request.metadata.filename)
        if request.metadata.flavors:
            file_object.update_ext_flavors([flavor
                                            for flavor in request.metadata.flavors])
        if request.metadata.metadata:
            file_object.update_ext_metadata({key: value
                                            for (key, value) in request.metadata.metadata.items()})
        if request.retrieve:
            cli_bundle = request.retrieve.bundle
            cli_case = request.retrieve.case

        location_type = location.get('type')
        if location_type == 'amazon':
            pass
        elif location_type == 'google':
            pass
        elif location_type == 'swift':
            pass
        elif location_type == 'http':
            data = lib.retrieve_from_http(location)
            file_object.append_data(data)

        response = strelka_pb2.Response(uid=cli_req['uid'])
        scan_result = lib.init_scan_result(cli_req)
        lib.distribute(file_object, scan_result, context)
        scan_result = lib.fin_scan_result(scan_result)

        if self.logger is not None:
            srv_evt = lib.result_to_evt(scan_result, self.bundle, self.case)
            if isinstance(srv_evt, list):
                for e in srv_evt:
                    self.logger.info(e)
            else:
                self.logger.info(srv_evt)

        if cli_bundle is not None and cli_case is not None:
            cli_evt = lib.result_to_evt(scan_result, cli_bundle, cli_case)
            if isinstance(cli_evt, list):
                response.events.extend(cli_evt)
            else:
                response.events.append(cli_evt)

        response.elapsed = time.time() - init_time
        return response

    def load_cfg(self):
        """Load Strelka configuration settings."""
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
    max_rpcs = conf.strelka_cfg.get('max_rpcs', DEFAULTS['max_rpcs'])
    max_workers = conf.strelka_cfg.get('max_workers', DEFAULTS['max_workers'])

    for addr in addresses:
        new_proc = StrelkaWrapper(addr, max_rpcs, max_workers)
        new_proc.start()
        proc_map[addr] = new_proc

    while run:
        for (addr, proc) in list(proc_map.items()):
            if not proc.is_alive():
                proc.join()
                del proc_map[addr]
                new_proc = StrelkaWrapper(addr, max_rpcs, max_workers)
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
