#!/usr/bin/env python
"""
validate_yara.py

Command line utility to validate a directory of YARA rules files.
"""
import argparse
import glob
import sys

import yara


def main():
    parser = argparse.ArgumentParser(prog="validate_yara.py",
                                     description="validates YARA rules files.",
                                     usage="%(prog)s [options]")
    parser.add_argument("-p", "--path",
                        dest="path",
                        help="path to directory containing YARA rules")
    parser.add_argument("-e", "--error",
                        action="store_true",
                        default=False,
                        dest="error",
                        help="boolean that determines if warnings should"
                             " cause errors")
    args = parser.parse_args()

    path = args.path or None
    error = args.error
    if path is None:
        sys.exit("Please provide a path.")

    globbed_paths = glob.iglob(f"{path}/**/*.yar*", recursive=True)
    for (idx, entry) in enumerate(globbed_paths):
        try:
            if error:
                yara.compile(filepath=entry, error_on_warning=True)
            else:
                yara.compile(filepath=entry)
        except (yara.Error, yara.SyntaxError) as YaraError:
            print(YaraError)


if __name__ == "__main__":
    main()
