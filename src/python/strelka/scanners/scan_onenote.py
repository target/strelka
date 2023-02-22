# Authors: Ryan Borre

import binascii
import re

from strelka.cstructs.onenote import FileDataStoreObject

from strelka import strelka


class ScanOnenote(strelka.Scanner):
    """Extracts embedded files in OneNote files."""

    def scan(self, data, file, options, expire_at):
        try:
            # For every embedded file, extract payload and submit back into Strelka pipeline
            for match in re.finditer(
                binascii.unhexlify(b"e716e3bd65261145a4c48d4d0b7a9eac"), data
            ):
                obj = FileDataStoreObject.parse(data[match.span(0)[0] :])

                # Send extracted file back to Strelka
                self.emit_file(obj.FileData)
        except Exception as e:
            self.flags.append(f"{self.__class__.__name__} Exception: {str(e)[:50]}")
