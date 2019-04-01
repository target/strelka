from OpenSSL import crypto

from strelka import core


class ScanPkcs7(core.StrelkaScanner):
    """Extracts files from PKCS7 certificate files."""
    def scan(self, data, file_object, options):
        self.metadata['total'] = {'certificates': 0, 'extracted': 0}

        if data[:1] == b'0':
            crypto_file_type = crypto.FILETYPE_ASN1
            self.metadata['cryptoType'] = 'der'
        else:
            crypto_file_type = crypto.FILETYPE_PEM
            self.metadata['cryptoType'] = 'pem'

        try:
            pkcs7 = crypto.load_pkcs7_data(crypto_file_type, data)
            pkcs7_certificates = pkcs7.get_certificates()
            if pkcs7_certificates is not None:
                self.metadata['total']['certificates'] = len(pkcs7_certificates)
                for certificate in pkcs7_certificates:
                    file_ = core.StrelkaFile(
                        name=f'sn_{certificate.get_serial_number()}',
                        source=self.scanner_name,
                    )
                    file_data = crypto.dump_certificate(
                        crypto_file_type,
                        certificate,
                    )
                    self.r0.setex(
                        file_.uid,
                        self.expire,
                        file_data,
                    )
                    self.files.append(file_)
                    self.metadata['total']['extracted'] += 1

        except crypto.Error:
            self.flags.add(f'{self.scanner_name}::load_pkcs7_error')
