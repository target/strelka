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
        metadata_identifiers: List of YARA rule metadata identifiers
            (e.g. 'Author') that should be logged as metadata.
            Defaults to empty list.
    """
    def init(self):
        self.compiled_yara = None

    def scan(self, data, file, options, expire_at):
        location = options.get('location', '/etc/yara/')
        metadata_identifiers = options.get('metadata_identifiers', [])

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

        self.event.setdefault('matches', [])
        self.event.setdefault('metadata', [])

        try:
            if self.compiled_yara is not None:
                yara_matches = self.compiled_yara.match(data=data)
                for match in yara_matches:
                    self.event['matches'].append(match.rule)
                    if metadata_identifiers and match.meta:
                        for (key, value) in match.meta.items():
                            if key in metadata_identifiers:
                                yara_entry = {
                                    'rule': match.rule,
                                    'identifier': key,
                                    'value': value,
                                }
                                if yara_entry not in self.event['metadata']:
                                    self.event['metadata'].append(yara_entry)

        except (yara.Error, yara.TimeoutError):
            self.flags.append('scanning_error')
