import gzip
import io

from strelka import core
from strelka.scanners import util


class ScanGzip(core.StrelkaScanner):
    """Decompresses gzip files."""
    def scan(self, st_file, options):
        with io.BytesIO(self.data) as gzip_io:
            with gzip.GzipFile(fileobj=gzip_io) as gzip_file:
                decompressed_file = gzip_file.read()
                decompressed_size = len(decompressed_file)
                self.metadata['decompressedSize'] = decompressed_size

                ex_file = core.StrelkaFile(
                    source=self.name,
                )
                for c in util.chunk_string(decompressed_file):
                    p = self.fk.pipeline()
                    p.rpush(ex_file.uid, c)
                    p.expire(ex_file.uid, self.expire)
                    p.execute()
                self.files.append(ex_file)
