import ast
import plistlib
import xml

from strelka import strelka


class ScanPlist(strelka.Scanner):
    """Parses keys found in property list files.

    Options:
        keys: plist key values to log in the event.
            Defaults to all.
    """

    def scan(self, data, file, options, expire_at):
        keys = options.get("keys", [])

        try:
            plist = plistlib.loads(data)

            self.event["keys"] = []
            if isinstance(plist, dict):
                for k, v in plist.items():
                    if keys and k not in keys:
                        continue

                    try:
                        v = ast.literal_eval(v)
                    except (ValueError, SyntaxError):
                        pass

                    self.event["keys"].append(
                        {
                            "key": k,
                            "value": v,
                        }
                    )
        except xml.parsers.expat.ExpatError:
            self.flags.append("invalid_format")
