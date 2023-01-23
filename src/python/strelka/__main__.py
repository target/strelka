import argparse
import logging
import os
import sys
import time

import yaml

from strelka import strelka


def main():
    parser = argparse.ArgumentParser(
        prog="strelka",
        description="",
        usage="%(prog)s [options]",
    )
    parser.add_argument("filename")

    args = parser.parse_args()

    print("starting local analysis...", file=sys.stderr)

    if os.path.exists("/etc/strelka/backend.yaml"):
        backend_cfg_path = "/etc/strelka/backend.yaml"
    elif os.path.exists("/home/karl/strelka/configs/python/backend/backend.yaml"):
        backend_cfg_path = "/home/karl/strelka/configs/python/backend/backend.yaml"
    else:
        logging.exception("no backend configuration found")
        sys.exit(1)

    with open(backend_cfg_path) as f:
        backend_cfg = yaml.safe_load(f.read())

        backend_cfg["tasting"][
            "yara_rules"
        ] = "/home/karl/strelka/src/python/strelka/config/taste.yara"

        backend = strelka.Backend(backend_cfg)

        with open(args.filename, "rb") as analysis_file:
            data = analysis_file.read()
            flavors = backend.match_flavors(data)

            file = strelka.File(name=analysis_file.name, data=data)

            events = backend.distribute(file.uid, file, int(time.time()) + 300)

            for event in events:
                print(strelka.format_event(event))


if __name__ == "__main__":
    main()
