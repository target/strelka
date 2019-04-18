import io
import lzma

from strelka import strelka


class ScanLzma(strelka.Scanner):
    """Decompresses LZMA files."""
    def scan(self, data, file, options, expire_at):
        try:
            with io.BytesIO(data) as data:
                with lzma.LZMAFile(filename=data) as st_tmp:
                    try:
                        decompressed_file = st_tmp.read()
                        decompressed_size = len(decompressed_file)
                        self.metadata['decompressed_size'] = decompressed_size

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
