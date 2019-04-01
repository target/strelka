import gzip
import io

from strelka import core


class ScanGzip(core.StrelkaScanner):
    """Decompresses gzip files."""
    def scan(self, data, file_object, options):
        with io.BytesIO(data) as gzip_io:
            with gzip.GzipFile(fileobj=gzip_io) as gzip_file:
                decompressed_file = gzip_file.read()
                decompressed_size = len(decompressed_file)
                self.metadata['decompressedSize'] = decompressed_size
                file_ = core.StrelkaFile(
                    source=self.scanner_name,
                )
                self.r0.setex(
                    file_.uid,
                    self.expire,
                    decompressed_file,
                )
                self.files.append(file_)
