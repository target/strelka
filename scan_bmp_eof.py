from strelka import strelka

class ScanBmpEof(strelka.Scanner):
    """
    Take the data of the BMP image, parse it, and determine if data is stored beyond
    the expected marker.
    """
    def scan(self, data, file, options, expire_at):
        expectedSize = int.from_bytes(data[2:6], "little")
        actualSize = len(data)
        if expectedSize != actualSize:
            self.event['trailer_index'] = expectedSize
            trailer_bytes_data = data[expectedSize:]
            extract_file = strelka.File(
                source=self.name,
            )

            for c in strelka.chunk_string(trailer_bytes_data):
                self.upload_to_coordinator(
                    extract_file.pointer,
                    c,
                    expire_at,
                )
            self.event['BMP_EOF'] = data[expectedSize:]
            self.files.append(extract_file)
        else:
            self.flags.append('no_trailer')