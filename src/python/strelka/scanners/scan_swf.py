import io
import struct
import zlib

from strelka import strelka

# NOTE: `pylzma` is an optional, unpinned dependency. It is abandoned (last
# release ~2014) and does not build on Python 3.10+, so it was removed from
# pyproject.toml. It is only needed to decompress LZMA-compressed ("ZWS") SWF
# files. Import it lazily inside the ZWS branch (below) instead of at module
# load time: a top-level import here is unguarded and raises ModuleNotFoundError
# on import, which crashes the entire backend at startup (check_scanners()
# imports every configured scanner). With the lazy import, the backend boots and
# only an actual ZWS file degrades gracefully with a flag. To restore ZWS
# support, install a maintained LZMA library and update this branch accordingly.


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
                # Lazy import: see module-level note. pylzma is optional and may
                # not be installed; only ZWS (LZMA) SWF files need it.
                try:
                    import pylzma
                except ImportError:
                    self.flags.append("pylzma_unavailable")
                    return

                swf_io.seek(12)
                extract_data += pylzma.decompress(swf_io.read())[: swf_size - 8]

                # Send extracted file back to Strelka
                self.emit_file(extract_data)

            elif magic == b"FWS":
                self.event["type"] = "FWS"
