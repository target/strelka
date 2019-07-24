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

                    except EOFError:
                        self.flags.append('eof_error')

        except lzma.LZMAError:
            self.flags.append('lzma_error')
