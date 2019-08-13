import ast
import plistlib

from strelka import strelka


class ScanPlist(strelka.Scanner):
    """Parses keys found in property list files.

    Options:
        keys: plist key values to log in the event.
            Defaults to all.
    """
    def scan(self, data, file, options, expire_at):
        keys = options.get('keys', [])

        plist = plistlib.loads(data)

        self.event['keys'] = []
        for k, v in plist.items():
            if keys and k not in keys:
                continue

            try:
                v = ast.literal_eval(v)
            except (ValueError, SyntaxError):
                pass

            self.event['keys'].append({
                'key': k,
                'value': v,
            })
