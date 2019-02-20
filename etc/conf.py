import yaml

scan_cfg = {}
strelka_cfg = {}


def load_scan(path):
    """Loads 'scan.yaml' into memory."""
    global scan_cfg
    with open(path) as f:
        scan_cfg = yaml.safe_load(f.read())


def load_strelka(path):
    """Loads 'strelka.yaml' into memory."""
    global strelka_cfg
    with open(path) as f:
        strelka_cfg = yaml.safe_load(f.read())
