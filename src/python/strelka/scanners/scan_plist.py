import plistlib

import inflection

from strelka import strelka


class ScanPlist(strelka.Scanner):
    """Parses keys found in property list files.

    Options:
        keys: plist key values to log in the event.
            Defaults to all.
    """
    def scan(self, data, file, options, expire_at):
        keys = options.get('keys', ['Label'])

        plist = plistlib.loads(data)

        self.event['keys'] = []
        for k, v in plist.items():
            if k not in self.event['keys']:
                self.event['keys'].append(k)

            if keys and k not in keys:
                pass

            k = inflection.underscore(k)
            self.event[k] = v
