# Authors: Ryan Borre

import binascii
import hashlib
import re

from strelka import strelka
from strelka.cstructs.onenote import FileDataStoreObject


class ScanOnenote(strelka.Scanner):
    """Extracts embedded files in OneNote files."""

    def scan(self, data, file, options, expire_at):
        for match in re.finditer(
            binascii.unhexlify(b"e716e3bd65261145a4c48d4d0b7a9eac"), data
        ):
            fdso = FileDataStoreObject.parse(data[match.span(0)[0] :])
            payload = fdso.FileData

            extract_file = strelka.File(
                source=self.name, name=hashlib.sha256(payload).hexdigest()
            )

            for c in strelka.chunk_string(payload):
                self.upload_to_coordinator(
                    extract_file.pointer,
                    c,
                    expire_at,
                )
            self.files.append(extract_file)
