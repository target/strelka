from strelka import strelka


class ScanFooter(strelka.Scanner):
    """Collects file footer.

    Options:
        length: Number of footer characters to log as metadata.
            Defaults to 50.
    """
    def scan(self, data, file, options, expire_at):
        length = options.get('length', 50)

        self.event['footer'] = data[:length]
