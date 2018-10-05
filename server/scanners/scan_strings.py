import re

from server import objects


class ScanStrings(objects.StrelkaScanner):
    """Collects strings from files.

    Collects strings from files (similar to the output of the Unix "strings"
    utility).

    Options:
        limit: Maximum number of strings to collect, starting from the
            beginning of the file. If this value is 0, then all strings are
            collected.
            Defaults to 0 (unlimited).
    """
    def init(self):
        self.strings_regex = re.compile(br"[^\x00-\x1F\x7F-\xFF]{4,}")

    def scan(self, file_object, options):
        limit = options.get("limit", 0)

        strings = self.strings_regex.findall(file_object.data)
        if limit:
            strings = strings[:limit]
        self.metadata["strings"] = strings
