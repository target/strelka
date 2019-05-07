from strelka import strelka


class ScanJpeg(strelka.Scanner):
    """Extracts data embedded in JPEG files.

    This scanner extracts data that is inserted past the JFIF trailer.
    """
    def scan(self, data, file, options, expire_at):
        if not data.endswith(b'\xff\xd9'):
            trailer_index = data.rfind(b'\xff\xd9')
            if trailer_index == -1:
                self.flags.append('no_trailer')
            else:
                trailer_data = data[trailer_index + 2:]
                if trailer_data:
                    self.event['trailer_index'] = trailer_index

                    extract_file = strelka.File(
                        source=self.name,
                    )

                    for c in strelka.chunk_string(trailer_data):
                        self.upload_to_cache(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                    self.files.append(extract_file)
