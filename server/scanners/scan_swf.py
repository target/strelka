import io
import pylzma
import struct
import zlib

from server import lib


class ScanSwf(lib.StrelkaScanner):
    """Decompresses SWF files."""
    def scan(self, file_object, options):
        with io.BytesIO(file_object.data) as swf_object:
            swf_object.seek(4)
            swf_size = struct.unpack('<i', swf_object.read(4))[0]
            swf_object.seek(0)
            magic = swf_object.read(3)
            child_file = b'FWS' + swf_object.read(5)

            if magic == b'CWS':
                self.metadata['type'] = 'CWS'
                try:
                    child_file += zlib.decompress(swf_object.read())[:swf_size - 8]
                    child_filename = f'{self.scanner_name}::size_{len(child_file)}'
                    child_fo = lib.StrelkaFile(data=child_file,
                                               filename=child_filename,
                                               depth=file_object.depth + 1,
                                               parent_uid=file_object.uid,
                                               root_uid=file_object.root_uid,
                                               parent_hash=file_object.hash,
                                               root_hash=file_object.root_hash,
                                               source=self.scanner_name)
                    self.children.append(child_fo)

                except zlib.error:
                    file_object.flags.append(f'{self.scanner_name}::zlib_error')
            elif magic == b'ZWS':
                self.metadata['type'] = 'ZWS'
                swf_object.seek(12)
                child_file += pylzma.decompress(swf_object.read())[:swf_size - 8]
                child_filename = f'{self.scanner_name}::size_{len(child_file)}'
                child_fo = lib.StrelkaFile(data=child_file,
                                           filename=child_filename,
                                           depth=file_object.depth + 1,
                                           parent_uid=file_object.uid,
                                           root_uid=file_object.root_uid,
                                           parent_hash=file_object.hash,
                                           root_hash=file_object.root_hash,
                                           source=self.scanner_name)
                self.children.append(child_fo)
            elif magic == b'FWS':
                self.metadata['type'] = 'FWS'
