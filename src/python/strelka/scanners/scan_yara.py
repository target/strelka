import copy
import glob
import hashlib
import logging
import math
import os
import time

import yara

from strelka import strelka, yara_extern

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

        compiled_custom_yara_all = ''
        if options.get('compiled_custom_yara_all'):
            # custom yara was provided - use it to evaluate this file
            compiled_custom_yara_all = options['compiled_custom_yara_all']

        # Support some common external variables (backcompat)
        # The file and data extractions are not available with pre-compiled yara;
        # in this case, all externals values will be an empty string
        externals = copy.copy(yara_extern.EXTERNAL_VARS)
        externals['filename'] = file.name
        externals['file_name'] = file.name
        extension = file.name.split('.')[-1]
        if extension:
            externals['extension'] = '.' + file.name.split('.')[-1]
            externals['filetype'] = extension
            externals['file_type'] = extension
        externals['md5'] = hashlib.md5(data).hexdigest()
        externals['sha1'] = hashlib.sha1(data).hexdigest()
        externals['sha256'] = hashlib.sha256(data).hexdigest()

        try:
            if self.compiled_yara is None and os.path.exists(location):
                if os.path.isdir(location):
                    globbed_yara_paths = glob.iglob(f'{location}/**/*.yar*', recursive=True)
                    yara_filepaths = {f'namespace_{i}':entry for (i, entry) in enumerate(globbed_yara_paths)}
                    if yara_filepaths:
                        self.compiled_yara = yara.compile(filepaths=yara_filepaths, externals=externals)
                else:
                    self.compiled_yara = yara.compile(filepath=location, externals=externals)

        except (yara.Error, yara.SyntaxError):
            self.flags.append('compiling_error')

        self.event['matches'] = []

        try:
            yara_matches = []

            timeout = math.ceil(expire_at - time.time())

            if self.compiled_yara is not None:
                yara_matches = self.compiled_yara.match(data=data, timeout=timeout)

            if compiled_custom_yara_all:
                timeout = math.ceil(expire_at - time.time())
                yara_matches = compiled_custom_yara_all.match(data=data, timeout=timeout)

            for match in yara_matches:
                event = { 'name': match.rule, 'tags': [], 'meta': {} }
                if match.tags:
                    for tag in match.tags:
                        if not tag in event['tags']:
                            event['tags'].append(tag)

                for k, v in match.meta.items():
                    if meta and k not in meta:
                        continue

                    event['meta'][k] = v

                self.event['matches'].append(event)

        except (yara.Error, yara.TimeoutError):
            self.flags.append('scanning_error')
