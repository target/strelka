#!/usr/bin/env python3

from server import objects
from server import distribution
from shared import conf
import sys

CONF_PATH = "etc/strelka/strelka.yml"

def main():
    if len(sys.argv) != 2 :
        print("usage: {} filepath".format(sys.argv[0]))
        sys.exit()
    config = conf.parse_yaml(path = CONF_PATH, section = "scan")
    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        print("argument is not a filepath")
        sys.exit()
    with open(filepath, 'rb') as f:
        data = f.read()
        file_object = objects.StrelkaFile(data = data,
                filename = os.path.basename(filepath),
                source="Standalone",
                external_flavors= [],
                external_metadata=[])
        scan_result = {"results": []}
        distribution.distribute(file_object, scan_result)
        print(scan_result)


