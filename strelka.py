#!/usr/bin/env python3
import argparse
from concurrent import futures
import logging.config
import os
import signal
import sys
import time
import uuid
import yaml

import grpc
import pebble

from etc import conf
from server import lib
import strelka_pb2
import strelka_pb2_grpc


class StrelkaServicer(strelka_pb2_grpc.StrelkaServicer):
    def __init__(self, pool):
        self.pool = pool
        self.tmp_directory = conf.server_cfg.get('tmp_directory',
                                                 conf.defaults['tmp_directory'])

        path = conf.server_cfg.get('srv_path', conf.defaults['srv_path'])
        self.bundle = conf.server_cfg.get('srv_bundle')
        self.case = conf.server_cfg.get('srv_case')
        self.logger = logging.getLogger('strelka')
        self.logger.propagate = False
        self.logger.addHandler(logging.handlers.WatchedFileHandler(path,
                                                                   delay=True))

    def StreamData(self, request_iterator, context):
        file_object = lib.StrelkaFile()
        response = strelka_pb2.ScanResult()
        tmp_file = os.path.join(self.tmp_directory, str(uuid.uuid4()))

        with open(tmp_file, 'wb') as f:
            for request in request_iterator:
                f.write(request.data)
                response.uid = request.request.uid
                cli_request = {'uid': request.request.uid,
                               'client': request.request.client,
                               'source': request.request.source}
                file_object.filename = request.metadata.filename
                file_object.add_ext_flavors([flavor
                                             for flavor in request.metadata.flavors])
                file_object.add_ext_metadata({key: value
                                              for (key, value) in request.metadata.metadata.items()})
                cli_response = {'bundle': request.retrieve.bundle,
                                'case': request.retrieve.case}

        try:
            future = self.pool.schedule(lib.schedule_data,
                                        args=[file_object, cli_request, tmp_file],
                                        timeout=context.time_remaining())

            srv_event = lib.result_to_evt(future.result(),
                                          self.bundle,
                                          self.case)
            for event in srv_event:
                self.logger.info(event)

            cli_event = lib.result_to_evt(future.result(),
                                          cli_response['bundle'],
                                          cli_response['case'])
            response.events.extend(cli_event)

        except futures.TimeoutError:
            context.abort(grpc.StatusCode.DEADLINE_EXCEEDED, 'Timeout')
        except pebble.common.ProcessExpired:
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, 'Abnormal termination')

        return response

    def SendLocation(self, request, context):
        file_object = lib.StrelkaFile()
        response = strelka_pb2.ScanResult()

        location = {key:
                    value for (key, value) in request.location.items()}
        response.uid = request.request.uid
        cli_request = {'uid': request.request.uid,
                       'client': request.request.client,
                       'source': request.request.source}
        file_object.filename = request.metadata.filename
        file_object.add_ext_flavors([flavor
                                     for flavor in request.metadata.flavors])
        file_object.add_ext_metadata({key: value
                                      for (key, value) in request.metadata.metadata.items()})
        cli_response = {'bundle': request.retrieve.bundle,
                        'case': request.retrieve.case}

        try:
            future = self.pool.schedule(lib.schedule_location,
                                        args=[file_object, cli_request, location],
                                        timeout=context.time_remaining())

            srv_event = lib.result_to_evt(future.result(),
                                          self.bundle,
                                          self.case)
            for event in srv_event:
                self.logger.info(event)

            cli_event = lib.result_to_evt(future.result(),
                                          cli_response['bundle'],
                                          cli_response['case'])
            response.events.extend(cli_event)

        except TimeoutError:
            context.abort(grpc.StatusCode.DEADLINE_EXCEEDED, 'Timeout')
        except pebble.common.ProcessExpired:
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, 'Abnormal termination')

        return response


RUN = 1


def main():
    def handler(sig, frame):
        global RUN
        RUN = 0

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)

    parser = argparse.ArgumentParser(prog='strelka.py',
                                     description='runs Strelka server',
                                     usage='%(prog)s [options]')
    parser.add_argument('-c', '--server-config',
                        action='store',
                        dest='server_cfg',
                        help='path to server configuration file')
    args = parser.parse_args()

    server_cfg = ''
    if args.server_cfg:
        if not os.path.exists(args.server_cfg):
            sys.exit(f'server configuration {args.server_cfg} does not exist')
        server_cfg = args.server_cfg
    elif os.path.exists('/etc/strelka/server.yaml'):
        server_cfg = '/etc/strelka/server.yaml'

    if not server_cfg:
        sys.exit('no server configuration found')
    conf.load_server(server_cfg)

    logging_cfg = conf.server_cfg.get('logging_cfg',
                                      conf.defaults['logging_cfg'])
    with open(logging_cfg, 'r') as f:
        logging.config.dictConfig(yaml.safe_load(f.read()))
    logging.info(f'using strelka configuration {server_cfg}')

    address = conf.server_cfg.get('address',
                                  conf.defaults['address'])
    shutdown = conf.server_cfg.get('shutdown',
                                   conf.defaults['shutdown'])
    max_rpcs = conf.server_cfg.get('max_rpcs',
                                   conf.defaults['max_rpcs'])
    processes = conf.server_cfg.get('processes',
                                    conf.defaults['processes'])
    maxtasks = conf.server_cfg.get('maxtasks',
                                   conf.defaults['maxtasks'])

    pool = pebble.ProcessPool(max_workers=processes,
                              max_tasks=maxtasks)
    executor = futures.ThreadPoolExecutor(max_workers=processes)
    server = grpc.server(executor,
                         maximum_concurrent_rpcs=max_rpcs)
    strelka_pb2_grpc.add_StrelkaServicer_to_server(StrelkaServicer(pool), server)
    server.add_insecure_port(address)
    server.start()
    while RUN:
        time.sleep(5)
    stop = server.stop(shutdown)
    stop.wait()
    pool.stop()  # all RPCs are gone by this point
    pool.join(0)


if __name__ == '__main__':
    main()
