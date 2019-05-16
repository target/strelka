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
                        decompressed_file = lzma_obj.read()
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

        except lzma.LZMAError:
            self.flags.append('lzma_error')
