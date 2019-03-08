from server import lib


class ScanJpeg(lib.StrelkaScanner):
    """Extracts data embedded in JPEG files.

    This scanner extracts data that is inserted past the JFIF trailer.
    """
    def scan(self, file_object, options):
        if not file_object.data.endswith(b'\xff\xd9'):
            trailer_index = file_object.data.rfind(b'\xff\xd9')
            if trailer_index == -1:
                file_object.flags.append(f'{self.scanner_name}::no_trailer')
            else:
                trailer_data = file_object.data[trailer_index + 2:]
                if trailer_data:
                    self.metadata['trailerIndex'] = trailer_index
                    child_filename = f'{self.scanner_name}::size_{len(trailer_data)}'
                    child_fo = lib.StrelkaFile(data=trailer_data,
                                               filename=child_filename,
                                               depth=file_object.depth + 1,
                                               parent_uid=file_object.uid,
                                               root_uid=file_object.root_uid,
                                               parent_hash=file_object.hash,
                                               root_hash=file_object.root_hash,
                                               source=self.scanner_name)
                    self.children.append(child_fo)
