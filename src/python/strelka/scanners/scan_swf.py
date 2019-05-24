import io
import struct
import zlib

import pylzma

from strelka import strelka


class ScanSwf(strelka.Scanner):
    """Decompresses SWF files."""
    def scan(self, data, file, options, expire_at):
        with io.BytesIO(data) as swf_io:
            swf_io.seek(4)
            swf_size = struct.unpack('<i', swf_io.read(4))[0]
            swf_io.seek(0)
            magic = swf_io.read(3)
            extract_data = b'FWS' + swf_io.read(5)

            if magic == b'CWS':
                self.event['type'] = 'CWS'
                try:
                    extract_data += zlib.decompress(swf_io.read())[:swf_size - 8]
                    extract_file = strelka.File(
                        source=self.name,
                    )

                    for c in strelka.chunk_string(extract_data):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                    self.files.append(extract_file)

                except zlib.error:
                    self.flags.append('zlib_error')

            elif magic == b'ZWS':
                self.event['type'] = 'ZWS'
                swf_io.seek(12)
                extract_data += pylzma.decompress(swf_io.read())[:swf_size - 8]
                extract_file = strelka.File(
                    source=self.name,
                )

                for c in strelka.chunk_string(extract_data):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

                self.files.append(extract_file)

            elif magic == b'FWS':
                self.event['type'] = 'FWS'
