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
        if 'author' not in meta:
            meta.append('author')
        if 'description' not in meta:
            meta.append('description')

        compiled_custom_yara = None
        if options.get('source'):
            # custom yara was provided - use it to evaluate this file
            try:
                compiled_custom_yara = yara.compile(source=options['source'])
            except (yara.Error, yara.SyntaxError):
                self.flags.append('compiling_error')

        try:
            if self.compiled_yara is None and os.path.exists(location):
                if os.path.isdir(location):
                    globbed_yara_paths = glob.iglob(f'{location}/**/*.yar*', recursive=True)
                    yara_filepaths = {f'namespace_{i}':entry for (i, entry) in enumerate(globbed_yara_paths)}
                    if yara_filepaths:
                        self.compiled_yara = yara.compile(filepaths=yara_filepaths)
                else:
                    self.compiled_yara = yara.compile(filepath=location)

        except (yara.Error, yara.SyntaxError):
            self.flags.append('compiling_error')

        self.event['matches'] = []

        try:
            yara_matches = []

            if self.compiled_yara is not None:
                yara_matches = self.compiled_yara.match(data=data)

            if compiled_custom_yara is not None:
                custom_yara_matches = compiled_custom_yara.match(data=data)
                yara_matches.extend(custom_yara_matches)

            for match in yara_matches:
                event = { 'name': match.rule, 'tags': [], 'meta': {} }
                if match.tags:
                    for tag in match.tags:
                        if not tag in self.event['tags']:
                            event['tags'].append(tag)

                for k, v in match.meta.items():
                    if meta and k not in meta:
                        continue

                    event['meta'][k] = v

                self.event['matches'].append(event)

        except (yara.Error, yara.TimeoutError):
            self.flags.append('scanning_error')
