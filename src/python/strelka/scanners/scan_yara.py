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
        location = options.get('location', '/etc/yara/')
        meta = options.get('meta', [])

        try:
            if self.compiled_yara is None:
                if os.path.isdir(location):
                    yara_filepaths = {}
                    globbed_yara_paths = glob.iglob(f'{location}/**/*.yar*', recursive=True)
                    for (idx, entry) in enumerate(globbed_yara_paths):
                        yara_filepaths[f'namespace_{idx}'] = entry
                    self.compiled_yara = yara.compile(filepaths=yara_filepaths)

                else:
                    self.compiled_yara = yara.compile(filepath=location)

        except (yara.Error, yara.SyntaxError):
            self.flags.append('compiling_error')

        self.event['matches'] = []
        self.event['meta'] = []

        try:
            if self.compiled_yara is not None:
                yara_matches = self.compiled_yara.match(data=data)
                for match in yara_matches:
                    self.event['matches'].append(match.rule)

                    for k, v in match.meta.items():
                        if meta and k not in meta:
                            continue

                        self.event['meta'].append({
                            'rule': match.rule,
                            'identifier': k,
                            'value': v,
                        })

        except (yara.Error, yara.TimeoutError):
            self.flags.append('scanning_error')
