import io
import pylzma
import struct
import zlib

from strelka import core


class ScanSwf(core.StrelkaScanner):
    """Decompresses SWF files."""
    def scan(self, data, file_object, options):
        with io.BytesIO(data) as swf_object:
            swf_object.seek(4)
            swf_size = struct.unpack('<i', swf_object.read(4))[0]
            swf_object.seek(0)
            magic = swf_object.read(3)
            file_data = b'FWS' + swf_object.read(5)

            if magic == b'CWS':
                self.metadata['type'] = 'CWS'
                try:
                    file_data += zlib.decompress(swf_object.read())[:swf_size - 8]
                    file_ = core.StrelkaFile(
                        source=self.scanner_name,
                    )
                    self.r0.setex(
                        file_.uid,
                        self.expire,
                        file_data,
                    )
                    self.files.append(file_)

                except zlib.error:
                    self.flags.add(f'{self.scanner_name}::zlib_error')

            elif magic == b'ZWS':
                self.metadata['type'] = 'ZWS'
                swf_object.seek(12)
                file_data += pylzma.decompress(swf_object.read())[:swf_size - 8]
                file_ = core.StrelkaFile(
                    source=self.scanner_name,
                )
                self.r0.setex(
                    file_.uid,
                    self.expire,
                    file_data,
                )
                self.files.append(file_)

            elif magic == b'FWS':
                self.metadata['type'] = 'FWS'
