import zlib

from strelka import strelka


class ScanZlib(strelka.Scanner):
    """Decompresses zlib files."""
    def scan(self, data, file, options, expire_at):
        decompressed = zlib.decompress(data)
        self.event["size"] = len(decompressed)

        # Send extracted file back to Strelka
        self.emit_file(decompressed, name=file.name)
