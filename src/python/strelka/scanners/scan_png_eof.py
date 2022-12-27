from strelka import strelka


class ScanPngEof(strelka.Scanner):
    """Extract data embeded in PNG files.

    This scanner extracts data that is inserted past the PNG file end
    """

    def scan(self, data, file, options, expire_at):

        # PNG IEND chunk
        png_iend = b"\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82"

        # A normal PNG file should end with the IEND chunk
        if data.endswith(png_iend):
            self.flags.append("no_trailer")
        else:
            # Locate the first occurance of the IEND chunk, the end of PNG file
            if -1 != (trailer_index := data.find(png_iend)):

                trailer_index = trailer_index + len(png_iend)
                self.event["trailer_index"] = trailer_index

                extract_file = strelka.File(source=self.name)
                self.event["PNG_EOF"] = data[trailer_index:]

                for c in strelka.chunk_string(data[trailer_index:]):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

                self.files.append(extract_file)
            else:
                self.flags.append("no_iend_chunk")
