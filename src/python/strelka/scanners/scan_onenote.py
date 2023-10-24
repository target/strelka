# Authors: Ryan Borre, Paul Hutelmyer

import binascii
import re

from strelka import strelka
from strelka.cstructs.onenote import FileDataStoreObject

# This is the binary string we're searching for in the data.
ONE_NOTE_MAGIC = binascii.unhexlify(b"e716e3bd65261145a4c48d4d0b7a9eac")


class ScanOnenote(strelka.Scanner):
    """Extracts embedded files in OneNote files."""

    def scan(self, data, file, options, expire_at):
        self.event["total"] = {"files": 0, "extracted": 0}

        try:
            # Searching for the magic string in the data
            for match in re.finditer(ONE_NOTE_MAGIC, data):
                self.event["total"]["files"] += 1

                try:
                    # Parsing the found object
                    obj = FileDataStoreObject.parse(data[match.span(0)[0] :])

                    # Sending extracted file back to Strelka for further analysis
                    self.emit_file(obj.FileData)
                    self.event["total"]["extracted"] += 1
                except Exception as e:
                    self.flags.append(
                        f"{self.__class__.__name__} Exception: {str(e)[:50]}"
                    )
        except Exception as e:
            self.flags.append(f"{self.__class__.__name__} Exception: {str(e)[:50]}")
