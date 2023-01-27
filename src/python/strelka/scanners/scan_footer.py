import binascii

from strelka import strelka


class ScanFooter(strelka.Scanner):
    """Collects file footer.

    Options:
        length: Number of footer characters to log as metadata.
            Defaults to 50.
        encodings: List of which fields/encodings should be emitted, one of classic, raw, hex, backslash
    """

    def scan(self, data, file, options, expire_at):
        length = options.get("length", 50)
        encodings = options.get("encodings", ["classic"])

        if "classic" in encodings:
            self.event["footer"] = data[-length:]
        if "raw" in encodings:
            self.event["raw"] = data[-length:]
        if "hex" in encodings:
            self.event["hex"] = binascii.hexlify(data[-length:])
        if "backslash" in encodings:
            self.event["backslash"] = str(data[-length:])[2:-1]
