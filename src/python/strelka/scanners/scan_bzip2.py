import bz2
import io

from strelka import strelka


class ScanBzip2(strelka.Scanner):
    """Decompresses bzip2 files."""
    def scan(self, data, file, options, expire_at):
        with io.BytesIO(data) as bzip2_io:
            with bz2.BZ2File(filename=bzip2_io) as bzip2_obj:
                try:
                    decompressed_file = bzip2_obj.read()
                    decompressed_size = len(decompressed_file)
                    self.event['decompressed_size'] = decompressed_size

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

                except EOFError:
                    self.flags.append('eof_error')
                except OSError:
                    self.flags.append('os_error')
