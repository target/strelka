from OpenSSL import crypto

from strelka import core
from strelka.scanners import util


class ScanPkcs7(core.StrelkaScanner):
    """Extracts files from PKCS7 certificate files."""
    def scan(self, st_file, options):
        self.metadata['total'] = {'certificates': 0, 'extracted': 0}

        if self.data[:1] == b'0':
            crypto_file_type = crypto.FILETYPE_ASN1
            self.metadata['cryptoType'] = 'der'
        else:
            crypto_file_type = crypto.FILETYPE_PEM
            self.metadata['cryptoType'] = 'pem'

        try:
            pkcs7 = crypto.load_pkcs7_data(crypto_file_type, self.data)
            pkcs7_certificates = pkcs7.get_certificates()
            if pkcs7_certificates is not None:
                self.metadata['total']['certificates'] = len(pkcs7_certificates)
                for certificate in pkcs7_certificates:
                    ex_file = core.StrelkaFile(
                        name=f'sn_{certificate.get_serial_number()}',
                        source=self.name,
                    )
                    ex_data = crypto.dump_certificate(
                        crypto_file_type,
                        certificate,
                    )
                    for c in util.chunk_string(ex_data):
                        p = self.fk.pipeline()
                        p.rpush(ex_file.uid, c)
                        p.expire(ex_file.uid, self.expire)
                        p.execute()
                    self.files.append(ex_file)

                    self.metadata['total']['extracted'] += 1

        except crypto.Error:
            self.flags.add('load_pkcs7_error')
