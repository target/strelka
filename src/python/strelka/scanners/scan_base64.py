import base64

from strelka import strelka


class ScanBase64(strelka.Scanner):
    """Decodes base64-encoded file."""

    def scan(self, data, file, options, expire_at):
        decoded = base64.b64decode(data)

        self.event["size"] = len(decoded)

        # Send extracted file back to Strelka
        self.emit_file(decoded)
