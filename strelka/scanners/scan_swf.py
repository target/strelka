import io
import pylzma
import struct
import zlib

from strelka import core
from strelka.scanners import util


class ScanSwf(core.StrelkaScanner):
    """Decompresses SWF files."""
    def scan(self, st_file, options):
        with io.BytesIO(self.data) as swf_io:
            swf_io.seek(4)
            swf_size = struct.unpack('<i', swf_io.read(4))[0]
            swf_io.seek(0)
            magic = swf_io.read(3)
            ex_data = b'FWS' + swf_io.read(5)

            if magic == b'CWS':
                self.metadata['type'] = 'CWS'
                try:
                    ex_data += zlib.decompress(swf_io.read())[:swf_size - 8]
                    ex_file = core.StrelkaFile(
                        source=self.name,
                    )
                    for c in util.chunk_string(ex_data):
                        p = self.fk.pipeline()
                        p.rpush(ex_file.uid, c)
                        p.expire(ex_file.uid, self.expire)
                        p.execute()
                    self.files.append(ex_file)

                except zlib.error:
                    self.flags.add('zlib_error')

            elif magic == b'ZWS':
                self.metadata['type'] = 'ZWS'
                swf_io.seek(12)
                ex_data += pylzma.decompress(swf_io.read())[:swf_size - 8]
                ex_file = core.StrelkaFile(
                    source=self.name,
                )
                for c in util.chunk_string(ex_data):
                    p = self.fk.pipeline()
                    p.rpush(ex_file.uid, c)
                    p.expire(ex_file.uid, self.expire)
                    p.execute()
                self.files.append(ex_file)

            elif magic == b'FWS':
                self.metadata['type'] = 'FWS'
