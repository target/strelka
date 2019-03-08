from server import lib


class ScanHeader(lib.StrelkaScanner):
    """Collects file header.

    Options:
        length: Number of header characters to log as metadata.
            Defaults to 50.
    """
    def scan(self, file_object, options):
        length = options.get('length', 50)

        header = file_object.data[:length]
        if header:
            self.metadata['header'] = header
