import bz2
import io

from strelka import core
from strelka.scanners import util


class ScanBzip2(core.StrelkaScanner):
    """Decompresses bzip2 files."""
    def scan(self, st_file, options):
        with io.BytesIO(self.data) as bzip2_io:
            with bz2.BZ2File(filename=bzip2_io) as bzip2_file:
                try:
                    decompressed_file = bzip2_file.read()
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

                except EOFError:
                    self.flags.add('eof_error')
                except OSError:
                    self.flags.add('os_error')
