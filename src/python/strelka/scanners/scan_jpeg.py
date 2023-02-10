import struct

from strelka import strelka


class ScanJpeg(strelka.Scanner):
    """Extracts data appended to JPEG files.

    This scanner extracts data that is inserted past the JFIF EOI marker.
    """

    def scan(self, data, file, options, expire_at):
        try:
            offset = 0

            # Skip check for length with these markers
            markers_zero_length = [
                b"\xff\xd0",
                b"\xff\xd1",
                b"\xff\xd2",
                b"\xff\xd3",
                b"\xff\xd4",
                b"\xff\xd5",
                b"\xff\xd6",
                b"\xff\xd7",
                b"\xff\xd8",
                b"\xff\x01",
            ]

            # Image must start with SOI
            try:
                if not data[offset:].startswith(b"\xff\xd8"):
                    self.flags.append("corrupt_jpeg_data_no_soi")
                    return
            except IndexError:
                self.flags.append("Error accessing data[offset:]")
                return

            # Skip SOI
            offset += 2
            while True:
                marker = data[offset : offset + 2]

                # Marker must start with 0xff
                if marker[0] != 0xFF:
                    self.flags.append("corrupt_jpeg_data_misaligned_marker")
                    break

                if marker in markers_zero_length:
                    offset += 2
                    continue
                # Start scan data (SOS)
                elif marker == b"\xff\xda":
                    offset += 2
                    while True:
                        # Fast forward until we find a marker that's not FF00
                        if data[offset] == 0xFF and data[offset + 1] != 0x00:
                            break
                        offset += 1
                    continue
                # EOI marker
                elif marker == b"\xff\xd9":
                    offset += 2
                    break
                else:
                    marker_length = struct.unpack(">H", data[offset + 2 : offset + 4])[
                        0
                    ]
                    offset += 2
                    offset += marker_length

            # If the end of the image is reached with no more data, return
            if offset >= len(data):
                self.flags.append("no_trailer")
                return

            if trailer_data := data[offset:]:
                self.event["trailer_index"] = offset

                # Send extracted file back to Strelka
                self.emit_file(trailer_data)
        except Exception:
            self.flags.append("jpeg_general_parsing_error")
            return
