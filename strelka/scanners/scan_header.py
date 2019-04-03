from strelka import core


class ScanHeader(core.StrelkaScanner):
    """Collects file header.

    Options:
        length: Number of header characters to log as metadata.
            Defaults to 50.
    """
    def scan(self, st_file, options):
        length = options.get('length', 50)

        self.metadata['header'] = self.data[:length]
