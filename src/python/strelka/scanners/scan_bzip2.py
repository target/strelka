import bz2
import io

from strelka import strelka


class ScanBzip2(strelka.Scanner):
    """Decompresses bzip2 files."""

    def scan(self, data, file, options, expire_at):
        with io.BytesIO(data) as bzip2_io:
            with bz2.BZ2File(filename=bzip2_io) as bzip2_obj:
                try:
                    decompressed = bzip2_obj.read()
                    self.event["size"] = len(decompressed)

                    # Send extracted file back to Strelka
                    self.emit_file(decompressed, name=file.name)

                except EOFError:
                    self.flags.append("eof_error")
                except OSError:
                    self.flags.append("os_error")
