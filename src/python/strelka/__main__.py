import argparse
import logging
import os
import sys
import time
from importlib.resources import files

import strelka.config
import strelka.strelka


def main():
    parser = argparse.ArgumentParser(
        prog="strelka",
        description="",
        usage="%(prog)s [options]",
    )
    parser.add_argument("filename")
    parser.add_argument("-c", "--backend_cfg_path")

    args = parser.parse_args()

    print("starting local analysis...", file=sys.stderr)

    if args.backend_cfg_path:
        config = strelka.config.BackendConfig(args.backend_cfg_path)
    elif os.path.exists(files("strelka.config").joinpath("backend.yaml")):
        config = strelka.config.BackendConfig(
            files("strelka.config").joinpath("backend.yaml")
        )
    else:
        config = strelka.config.BackendConfig()

    if config:
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

        if os.path.exists("/etc/strelka/logging.yaml"):
            logging_config_path = "/etc/strelka/logging.yaml"
        elif os.path.exists(files("strelka.config").joinpath("logging.yaml")):
            logging_config_path = str(files("strelka.config").joinpath("logging.yaml"))
        else:
            logging.exception("no logging configuration path found")
            sys.exit(1)

        backend_cfg = config.dictionary
        backend_cfg["tasting"]["yara_rules"] = taste_path
        backend_cfg["scanners"]["ScanYara"][0]["options"]["location"] = yara_rules_path
        backend_cfg["logging_cfg"] = logging_config_path

        backend = strelka.strelka.Backend(backend_cfg, disable_coordinator=True)

        with open(args.filename, "rb") as analysis_file:
            data = analysis_file.read()

            file = strelka.strelka.File(name=analysis_file.name, data=data)

            events = backend.distribute(file.uid, file, int(time.time()) + 300)

            for event in events:
                print(strelka.strelka.format_event(event))

    else:
        raise Exception("failed to initialize configuration")


if __name__ == "__main__":
    main()
