import argparse
import logging
import os
import sys
import time
from importlib.resources import files

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
    elif os.path.exists(files("strelka.config").joinpath("backend.yaml")):
        backend_cfg_path = files("strelka.config").joinpath("backend.yaml")
    else:
        logging.exception("no backend configuration found")
        sys.exit(1)

    if os.path.exists("/etc/strelka/taste/taste.yara"):
        taste_path = "/etc/strelka/taste/taste.yara"
    elif os.path.exists(files("strelka.config").joinpath("taste.yara")):
        taste_path = str(files("strelka.config").joinpath("taste.yara"))
    else:
        logging.exception("no taste path found")
        sys.exit(1)

    if os.path.exists("/etc/strelka/yara/rules.yara"):
        yara_rules_path = "/etc/strelka/yara/rules.yara"
    elif os.path.exists(files("strelka.config").joinpath("rules.yara")):
        yara_rules_path = str(files("strelka.config").joinpath("rules.yara"))
    else:
        logging.exception("no yara rules path found")
        sys.exit(1)

    with open(backend_cfg_path) as f:
        backend_cfg = yaml.safe_load(f.read())
        backend_cfg["tasting"]["yara_rules"] = taste_path
        backend_cfg["scanners"]["ScanYara"][0]["options"]["location"] = yara_rules_path

        backend = strelka.Backend(backend_cfg)

        with open(args.filename, "rb") as analysis_file:
            data = analysis_file.read()

            file = strelka.File(name=analysis_file.name, data=data)

            events = backend.distribute(file.uid, file, int(time.time()) + 300)

            for event in events:
                print(strelka.format_event(event))


if __name__ == "__main__":
    main()
