import gzip
import io

from strelka import strelka


class ScanGzip(strelka.Scanner):
    """Decompresses gzip files."""
    def scan(self, data, file, options, expire_at):
        with io.BytesIO(data) as gzip_io:
            with gzip.GzipFile(fileobj=gzip_io) as gzip_obj:
                decompressed = gzip_obj.read()
                self.event['size'] = len(decompressed)

                extract_file = strelka.File(
                    source=self.name,
                )

                for c in strelka.chunk_string(decompressed):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

                self.files.append(extract_file)
