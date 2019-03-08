import hashlib

from server import lib


class ScanSelf(lib.StrelkaScanner):
    """Collects metadata from the file's internal attributes.

    This scanners logs metadata that was defined during the creation of a
    file or metadata that provides basic information (e.g. file size) about
    a file.
    """
    def scan(self, file_object, options):
        self.metadata['filename'] = file_object.filename
        self.metadata['depth'] = file_object.depth
        self.metadata['uid'] = file_object.uid
        self.metadata['parentUid'] = file_object.parent_uid
        self.metadata['rootUid'] = file_object.root_uid
        self.metadata['hash'] = file_object.hash
        self.metadata['parentHash'] = file_object.parent_hash
        # self.metadata['rootHash'] = file_object.root_hash
        self.metadata['source'] = file_object.source
        self.metadata['scannerList'] = file_object.scanner_list
        self.metadata['size'] = len(file_object.data)
