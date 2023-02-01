from strelka import strelka


class ScanException(strelka.Scanner):
    """Collects strings from files.

    Collects strings from files (similar to the output of the Unix 'strings'
    utility).

    Options:
        limit: Maximum number of strings to collect, starting from the
            beginning of the file. If this value is 0, then all strings are
            collected.
            Defaults to 0 (unlimited).
    """

    def init(self):
        pass

    def scan(self, data, file, options, expire_at):
        raise Exception("Scanner Exception")
