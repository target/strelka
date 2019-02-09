import yaml

scan_cfg = {}
strelka_cfg = {}


def load_scan(path):
    global scan_cfg
    with open(path) as fin:
        scan_cfg = yaml.safe_load(fin.read())


def load_strelka(path):
    global strelka_cfg
    with open(path) as fin:
        strelka_cfg = yaml.safe_load(fin.read())
