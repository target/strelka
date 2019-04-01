import hashlib
import ssdeep

import redis

from strelka import core


class ScanHash(core.StrelkaScanner):
    """Calculates file hash values."""
    def scan(self, data, file_object, options):
        self.metadata['md5'] = hashlib.md5(data).hexdigest()
        self.metadata['sha1'] = hashlib.sha1(data).hexdigest()
        self.metadata['sha256'] = hashlib.sha256(data).hexdigest()
        self.metadata['ssdeep'] = ssdeep.hash(data)
