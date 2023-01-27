from strelka import strelka


class ScanGif(strelka.Scanner):
    """Extracts data embedded in GIF files.

    This scanner extracts data that is inserted past the GIF trailer.
    """

    def scan(self, data, file, options, expire_at):
        if not data.endswith(b"\x00\x3b"):
            trailer_index = data.rfind(b"\x00\x3b")
            if trailer_index == -1:
                self.flags.append("no_trailer")
            else:
                trailer_data = data[trailer_index + 2 :]
                if trailer_data:
                    self.event["trailer_index"] = trailer_index

                    # Send extracted file back to Strelka
                    self.emit_file(trailer_data)
