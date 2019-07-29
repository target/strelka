import plistlib

import inflection

from strelka import strelka


class ScanPlist(strelka.Scanner):
    """Collects metadata from JAR manifest files."""
    def scan(self, data, file, options, expire_at):
        keys = options.get('keys', ['Label'])

        plist = plistlib.loads(data)

        self.event['keys'] = []
        for k, v in plist.items():
            if k not in self.event['keys']:
                self.event['keys'].append(k)

            if k in keys:
                k = inflection.underscore(k)
                self.event[k] = v
