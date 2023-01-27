import io
import lzma

from strelka import strelka


class ScanLzma(strelka.Scanner):
    """Decompresses LZMA files."""

    def scan(self, data, file, options, expire_at):
        try:
            with io.BytesIO(data) as lzma_io:
                with lzma.LZMAFile(filename=lzma_io) as lzma_obj:
                    try:
                        decompressed = lzma_obj.read()
                        self.event["size"] = len(decompressed)

                        # Send extracted file back to Strelka
                        self.emit_file(decompressed, name=file.name)

                    except EOFError:
                        self.flags.append("eof_error")

        except lzma.LZMAError:
            self.flags.append("lzma_error")
