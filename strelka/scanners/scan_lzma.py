import io
import lzma

from strelka import core
from strelka.scanners import util


class ScanLzma(core.StrelkaScanner):
    """Decompresses LZMA files."""
    def scan(self, st_file, options):
        try:
            with io.BytesIO(self.data) as data:
                with lzma.LZMAFile(filename=data) as st_tmp:
                    try:
                        decompressed_file = st_tmp.read()
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

        except lzma.LZMAError:
            self.flags.add('lzma_error')
