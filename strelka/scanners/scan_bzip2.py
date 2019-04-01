import bz2
import io

from strelka import core


class ScanBzip2(core.StrelkaScanner):
    """Decompresses bzip2 files."""
    def scan(self, data, file_object, options):
        with io.BytesIO(data) as bzip2_io:
            with bz2.BZ2File(filename=bzip2_io) as bzip2_file:
                try:
                    decompressed_file = bzip2_file.read()
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
                except OSError:
                    self.flags.add(f'{self.scanner_name}::os_error')
