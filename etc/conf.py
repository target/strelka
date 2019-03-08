import multiprocessing

import yaml

scan_cfg = {}
server_cfg = {}

defaults = {
    'logging_cfg': '/etc/strelka/logging.yaml',
    'scan_cfg': '/etc/strelka/scan.yaml',
    'address': '[::]:8443',
    'shutdown': 30,
    'max_rpcs': None,
    'processes': multiprocessing.cpu_count(),
    'maxtasks': 500,
    'tmp_directory': '/tmp/',
    'srv_path': '/var/log/strelka/strelka.log',
    'srv_bundle': False,
    'srv_case': 'snake',
}


def load_scan(path):
    """Loads 'scan.yaml' into memory."""
    global scan_cfg
    with open(path) as f:
        scan_cfg = yaml.safe_load(f.read())


def load_server(path):
    """Loads 'server.yaml' into memory."""
    global server_cfg
    with open(path) as f:
        server_cfg = yaml.safe_load(f.read())
