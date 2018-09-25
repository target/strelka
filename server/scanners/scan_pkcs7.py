from OpenSSL import crypto

from server import objects


class ScanPkcs7(objects.StrelkaScanner):
    """Extracts files from PKCS7 certificate files."""
    def scan(self, file_object, options):
        self.metadata["total"] = {"certificates": 0, "extracted": 0}

        if file_object.data[:1] == b"0":
            crypto_file_type = crypto.FILETYPE_ASN1
            self.metadata["cryptoType"] = "der"
        else:
            crypto_file_type = crypto.FILETYPE_PEM
            self.metadata["cryptoType"] = "pem"

        try:
            pkcs7 = crypto.load_pkcs7_data(crypto_file_type, file_object.data)
            pkcs7_certificates = pkcs7.get_certificates()
            if pkcs7_certificates is not None:
                self.metadata["total"]["certificates"] = len(pkcs7_certificates)
                for certificate in pkcs7_certificates:
                    child_file = crypto.dump_certificate(crypto_file_type,
                                                         certificate)
                    child_filename = f"{self.scanner_name}::serial_number_{certificate.get_serial_number()}"
                    child_fo = objects.StrelkaFile(data=child_file,
                                                   filename=child_filename,
                                                   depth=file_object.depth + 1,
                                                   parent_uid=file_object.uid,
                                                   root_uid=file_object.root_uid,
                                                   parent_hash=file_object.hash,
                                                   root_hash=file_object.root_hash,
                                                   source=self.scanner_name)
                    self.children.append(child_fo)
                    self.metadata["total"]["extracted"] += 1

        except crypto.Error:
            file_object.flags.append(f"{self.scanner_name}::load_pkcs7_error")
