import gzip
import io

from strelka import strelka


class ScanGzip(strelka.Scanner):
    """Decompresses gzip files."""
    def scan(self, data, file, options, expire_at):
        with io.BytesIO(data) as gzip_io:
            with gzip.GzipFile(fileobj=gzip_io) as gzip_file:
                decompressed_file = gzip_file.read()
                decompressed_size = len(decompressed_file)
                self.metadata['decompressed_size'] = decompressed_size

                extract_file = strelka.File(
                    source=self.name,
                )

                for c in strelka.chunk_string(decompressed_file):
                    self.upload_to_cache(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

                self.files.append(extract_file)
