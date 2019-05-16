from strelka import strelka


class ScanHeader(strelka.Scanner):
    """Collects file header.

    Options:
        length: Number of header characters to log as metadata.
            Defaults to 50.
    """
    def scan(self, data, file, options, expire_at):
        length = options.get('length', 50)

        self.event['header'] = data[:length]
