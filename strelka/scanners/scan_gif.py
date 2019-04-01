from strelka import core


class ScanGif(core.StrelkaScanner):
    """Extracts data embedded in GIF files.

    This scanner extracts data that is inserted past the GIF trailer.
    """
    def scan(self, data, file_object, options):
        if not data.endswith(b'\x00\x3b'):
            trailer_index = data.rfind(b'\x00\x3b')
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
