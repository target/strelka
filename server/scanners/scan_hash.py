import hashlib
import ssdeep

from server import objects


class ScanHash(objects.StrelkaScanner):
    """Calculates file hash values."""
    def scan(self, file_object, options):
        self.metadata["md5"] = hashlib.md5(file_object.data).hexdigest()
        self.metadata["sha1"] = hashlib.sha1(file_object.data).hexdigest()
        self.metadata["sha256"] = hashlib.sha256(file_object.data).hexdigest()
        self.metadata["ssdeep"] = ssdeep.hash(file_object.data)
