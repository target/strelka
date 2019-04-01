from strelka import core


class ScanJpeg(core.StrelkaScanner):
    """Extracts data embedded in JPEG files.

    This scanner extracts data that is inserted past the JFIF trailer.
    """
    def scan(self, data, file_object, options):
        if not data.endswith(b'\xff\xd9'):
            trailer_index = data.rfind(b'\xff\xd9')
            if trailer_index == -1:
                self.flags.add(f'{self.scanner_name}::no_trailer')
            else:
                trailer_data = data[trailer_index + 2:]
                if trailer_data:
                    self.metadata['trailerIndex'] = trailer_index

                    file_ = core.StrelkaFile(
                        source=self.scanner_name,
                    )
                    self.r0.setex(
                        file_.uid,
                        self.expire,
                        trailer_data,
                    )
                    self.files.append(file_)
