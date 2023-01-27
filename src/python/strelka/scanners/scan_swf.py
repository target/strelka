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
            swf_size = struct.unpack("<i", swf_io.read(4))[0]
            swf_io.seek(0)
            magic = swf_io.read(3)
            extract_data = b"FWS" + swf_io.read(5)

            if magic == b"CWS":
                self.event["type"] = "CWS"
                try:
                    extract_data += zlib.decompress(swf_io.read())[: swf_size - 8]

                    # Send extracted file back to Strelka
                    self.emit_file(extract_data)

                except zlib.error:
                    self.flags.append("zlib_error")

            elif magic == b"ZWS":
                self.event["type"] = "ZWS"
                swf_io.seek(12)
                extract_data += pylzma.decompress(swf_io.read())[: swf_size - 8]

                # Send extracted file back to Strelka
                self.emit_file(extract_data)

            elif magic == b"FWS":
                self.event["type"] = "FWS"
