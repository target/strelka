import base64

from strelka import strelka


class ScanBase64(strelka.Scanner):
    """Decodes base64-encoded file."""
    def scan(self, data, file, options, expire_at):
        decoded = base64.b64decode(data)

        extract_file = strelka.File(
            source=self.name,
        )

        for c in strelka.chunk_string(decoded):
            self.upload_to_coordinator(
                extract_file.pointer,
                c,
                expire_at,
            )

        self.files.append(extract_file)
