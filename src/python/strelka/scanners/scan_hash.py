from hashlib import md5, sha1, sha256

from ssdeep import hash as ssdeep_hash
from tlsh import hash as tlsh_hash

from strelka import strelka


class ScanHash(strelka.Scanner):
    """Calculates file hash values."""

    def scan(self, data, file, options, expire_at):
        self.event["md5"] = md5(data).hexdigest()
        self.event["sha1"] = sha1(data).hexdigest()
        self.event["sha256"] = sha256(data).hexdigest()
        self.event["ssdeep"] = ssdeep_hash(data)
        self.event["tlsh"] = tlsh_hash(data)
