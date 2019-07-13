import zlib

from strelka import strelka


class ScanZlib(strelka.Scanner):
    """Decompresses zlib files."""
    def scan(self, data, file, options, expire_at):
        decompressed = zlib.decompress(data)
        self.event["size"] = len(decompressed)

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
