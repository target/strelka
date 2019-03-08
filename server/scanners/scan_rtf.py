from oletools import rtfobj

from server import lib


class ScanRtf(lib.StrelkaScanner):
    """Extracts files from RTF files.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, file_object, options):
        file_limit = options.get('limit', 1000)

        self.metadata['total'] = {'objects': 0, 'extracted': 0}

        rtf = rtfobj.RtfObjParser(file_object.data)
        rtf.parse()
        self.metadata['total']['objects'] = len(rtf.objects)

        for object in rtf.objects:
            if self.metadata['total']['extracted'] >= file_limit:
                break

            index = rtf.server.index(object)
            child_file = None
            child_filename = None
            if object.is_package:
                child_file = object.olepkgdata
                child_filename = f'{self.scanner_name}::{object.filename}'
            elif object.is_ole:
                child_file = object.oledata
                child_filename = f'{self.scanner_name}::object_{index}'
            else:
                child_file = object.rawdata
                child_filename = f'{self.scanner_name}:object_{index}'

            child_fo = lib.StrelkaFile(data=child_file,
                                       filename=child_filename,
                                       depth=file_object.depth + 1,
                                       parent_uid=file_object.uid,
                                       root_uid=file_object.root_uid,
                                       parent_hash=file_object.hash,
                                       root_hash=file_object.root_hash,
                                       source=self.scanner_name)
            self.children.append(child_fo)
            self.metadata['total']['extracted'] += 1
