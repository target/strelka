import hashlib
import ssdeep

import redis

from strelka import core


class ScanHash(core.StrelkaScanner):
    """Calculates file hash values."""
    def scan(self, st_file, options):
        self.metadata['md5'] = hashlib.md5(self.data).hexdigest()
        self.metadata['sha1'] = hashlib.sha1(self.data).hexdigest()
        self.metadata['sha256'] = hashlib.sha256(self.data).hexdigest()
        self.metadata['ssdeep'] = ssdeep.hash(self.data)
