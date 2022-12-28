import glob
import os

import yara

from strelka import strelka


class ScanYara(strelka.Scanner):
    """Scans files with YARA.

    Attributes:
        compiled_yara: Compiled YARA file derived from YARA rule file(s)
            in location.

    Options:
        location: Location of the YARA rules file or directory.
            Defaults to '/etc/yara/'.
        meta: List of YARA rule meta identifiers
            (e.g. 'Author') that should be logged.
            Defaults to empty list.
    """

    def init(self):
        self.compiled_yara = None

    def scan(self, data, file, options, expire_at):
        location = options.get("location", "/etc/strelka/yara/")
        meta = options.get("meta", [])

        try:
            if self.compiled_yara is None:
                if os.path.isdir(location):
                    globbed_yara_paths = glob.iglob(
                        f"{location}/**/*.yar*", recursive=True
                    )
                    if not globbed_yara_paths:
                        self.flags.append("yara_rules_not_found")
                    yara_filepaths = {
                        f"namespace_{i}": entry
                        for (i, entry) in enumerate(globbed_yara_paths)
                    }
                    self.compiled_yara = yara.compile(filepaths=yara_filepaths)

                elif os.path.isfile(location):
                    self.compiled_yara = yara.compile(filepath=location)
                else:
                    self.flags.append("yara_location_not_found")

        except yara.Error as e:
            self.flags.append(f"compiling_error_general_{e}")
        except yara.SyntaxError as e:
            self.flags.append(f"compiling_error_syntax_{e}")

        self.event["matches"] = []
        self.event["tags"] = []
        self.event["meta"] = []

        try:
            if self.compiled_yara is not None:
                yara_matches = self.compiled_yara.match(data=data)
                for match in yara_matches:
                    self.event["matches"].append(match.rule)
                    if match.tags:
                        for tag in match.tags:
                            if not tag in self.event["tags"]:
                                self.event["tags"].append(tag)

                    for k, v in match.meta.items():
                        if meta and k not in meta:
                            continue

                        self.event["meta"].append(
                            {
                                "rule": match.rule,
                                "identifier": k,
                                "value": v,
                            }
                        )

        except (yara.Error, yara.TimeoutError):
            self.flags.append("scanning_error")
