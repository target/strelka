"""Expose raw file data that has been compressed and encoded"""

import base64
import bz2
import gzip
import lzma

from strelka import strelka


class ScanSave(strelka.Scanner):
    """Compress and encode raw file data"""

    def init(self):
        # Compression algorithm choices
        self.compress_data = {
            "gzip": gzip.compress,
            "bzip2": bz2.compress,
            "lzma": lzma.compress,
        }
        # JSON compatible encoding choices
        self.encode_data = {
            "base64": base64.b64encode,
            "base85": base64.b85encode,
        }

    def scan(self, data, file, options, expire_at):
        # Inputs
        encoding = options.get("encoding", "base64")
        compression = options.get("compression", "gzip")

        # Compress the data
        if compression != "none":
            # Verify the compression algorithm is available
            if compression not in self.compress_data:
                self.flags.append("save_compression_value_error")
                return

            try:
                data = self.compress_data[compression](data)
            except strelka.ScannerTimeout:
                raise
            except Exception:
                self.flags.append("save_compression_error")
                return
        self.event["compression"] = compression

        # Verify the encoding algorithm is available
        if encoding not in self.encode_data:
            self.flag.append("save_encoding_value_error")
            return
        self.event["encoding"] = encoding

        # Encode the data for JSON compatibility
        try:
            out_data = self.encode_data[encoding](data)
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("save_encoding_error")
            return
        self.event["file"] = out_data
