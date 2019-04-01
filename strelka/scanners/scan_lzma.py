import io
import lzma

from strelka import core


class ScanLzma(core.StrelkaScanner):
    """Decompresses LZMA files."""
    def scan(self, data, file_object, options):
        try:
            with io.BytesIO(data) as data:
                with lzma.LZMAFile(filename=data) as f:
                    try:
                        decompressed_file = f.read()
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

                    except EOFError:
                        self.flags.add(f'{self.scanner_name}::eof_error')

        except lzma.LZMAError:
            self.flags.add(f'{self.scanner_name}::lzma_error')
