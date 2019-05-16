from OpenSSL import crypto

from strelka import strelka


class ScanPkcs7(strelka.Scanner):
    """Extracts files from PKCS7 certificate files."""
    def scan(self, data, file, options, expire_at):
        self.event['total'] = {'certificates': 0, 'extracted': 0}

        if data[:1] == b'0':
            crypto_file_type = crypto.FILETYPE_ASN1
            self.event['cryptoType'] = 'der'
        else:
            crypto_file_type = crypto.FILETYPE_PEM
            self.event['cryptoType'] = 'pem'

        try:
            pkcs7 = crypto.load_pkcs7_data(crypto_file_type, data)
            pkcs7_certificates = pkcs7.get_certificates()
            if pkcs7_certificates is not None:
                self.event['total']['certificates'] = len(pkcs7_certificates)
                for certificate in pkcs7_certificates:
                    extract_file = strelka.File(
                        name=f'sn_{certificate.get_serial_number()}',
                        source=self.name,
                    )

                    extract_data = crypto.dump_certificate(
                        crypto_file_type,
                        certificate,
                    )

                    for c in strelka.chunk_string(extract_data):
                        self.upload_to_cache(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                    self.files.append(extract_file)
                    self.event['total']['extracted'] += 1

        except crypto.Error:
            self.flags.append('load_pkcs7_error')
