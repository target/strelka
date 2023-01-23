import argparse
import importlib
import inflection
import os
import yaml
import logging
import sys

from strelka import strelka

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog="strelka",
        description="",
        usage="%(prog)s [options]",
    )
    parser.add_argument('filename')

    args = parser.parse_args()

    print("Starting local analysis...")

    if os.path.exists("/etc/strelka/backend.yaml"):
        backend_cfg_path = "/etc/strelka/backend.yaml"
    elif os.path.exists("/home/karl/strelka/configs/python/backend/backend.yaml"):
        backend_cfg_path = "/home/karl/strelka/configs/python/backend/backend.yaml"
    else:
        logging.exception("no backend configuration found")
        sys.exit(1)

    with open(backend_cfg_path) as f:
        backend_cfg = yaml.safe_load(f.read())

        backend_cfg["tasting"]["yara_rules"] = "/home/karl/strelka/src/python/strelka/config/taste.yara"

        coordinator = ""
        backend = strelka.Backend(backend_cfg, coordinator)

        with open(args.filename, "rb") as analysis_file:
            data = analysis_file.read()
            flavors = backend.match_flavors(data)

            file = strelka.File()
            file.add_flavors(backend.match_flavors(data))
            scanner_list = backend.match_scanners(file)

            files = []
            scanner_cache: dict = {}
            expire_at = None

            root_id = file.uid

            tree_dict = {
                'node': file.uid,
                'parent': file.parent,
                'root': root_id,
            }

            if file.depth == 0:
                tree_dict['node'] = root_id
            if file.depth == 1:
                tree_dict['parent'] = root_id

            file_dict = {
                'depth': file.depth,
                'name': file.name,
                'flavors': file.flavors,
                'scanners': [s.get('name') for s in scanner_list],
                'size': len(data),
                'source': file.source,
                'tree': tree_dict,
            }
            scan: dict = {}

            for scanner in scanner_list:
                try:
                    name = scanner['name']
                    und_name = inflection.underscore(name)
                    scanner_import = f'strelka.scanners.{und_name}'
                    module = importlib.import_module(scanner_import)
                    if und_name not in scanner_cache:
                        attr = getattr(module, name)(backend_cfg, coordinator)
                        scanner_cache[und_name] = attr
                    options = scanner.get('options', {})
                    plugin = scanner_cache[und_name]
                    (f, s) = plugin.scan_wrapper(
                        data,
                        file,
                        options,
                        expire_at,
                    )
                    files.extend(f)

                    scan = {
                        **scan,
                        **s,
                    }

                except ModuleNotFoundError:
                    logging.exception(f'scanner {scanner.get("name", "__missing__")} not found')

            event = {
                **{'file': file_dict},
                **{'scan': scan},
            }

            print(event)
