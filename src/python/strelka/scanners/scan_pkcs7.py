import tempfile

from M2Crypto import SMIME, X509

from strelka import strelka


class ScanPkcs7(strelka.Scanner):
    """Extracts files from PKCS7 certificate files."""
    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        self.event['total'] = {'certificates': 0, 'extracted': 0}

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            if data[:1] == b'0':
                pkcs7 = SMIME.load_pkcs7_der(tmp_data.name)
            else:
                pkcs7 = SMIME.load_pkcs7(tmp_data.name)

            certs = pkcs7.get0_signers(X509.X509_Stack())
            if certs:
                self.event['total']['certificates'] = len(certs)
                for cert in certs:
                    extract_file = strelka.File(
                        name=f'sn_{cert.get_serial_number()}',
                        source=self.name,
                    )

                    for c in strelka.chunk_string(cert.as_der()):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                    self.files.append(extract_file)
                    self.event['total']['extracted'] += 1
