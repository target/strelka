import gzip
import io

from strelka import strelka


class ScanGzip(strelka.Scanner):
    """Decompresses gzip files."""

    def scan(self, data, file, options, expire_at):
        with io.BytesIO(data) as gzip_io:
            with gzip.GzipFile(fileobj=gzip_io) as gzip_obj:
                decompressed = gzip_obj.read()
                self.event["size"] = len(decompressed)

                # Send extracted file back to Strelka
                self.emit_file(decompressed, name=file.name)
