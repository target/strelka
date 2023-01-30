import time

from M2Crypto import X509

from strelka import strelka


class ScanX509(strelka.Scanner):
    """Collects metadata from x509 and CRL files.

    x509 extensions require cleanup and may be improperly formatted.

    Options:
        type: String that determines the type of x509 certificate being
            scanned. Must be either 'der' or 'pem'.
            Defaults to empty string.
    """

    def scan(self, data, file, options, expire_at):
        file_type = options.get("type", "")

        if file_type == "der":
            cert = X509.load_cert_der_string(data)
        else:
            cert = X509.load_cert_string(data)

        self.event["issuer"] = cert.get_issuer().as_text()
        self.event["subject"] = cert.get_subject().as_text()
        self.event["serial_number"] = str(cert.get_serial_number())
        self.event["fingerprint"] = cert.get_fingerprint()
        self.event["version"] = cert.get_version()
        self.event["not_after"] = int(
            cert.get_not_after().get_datetime().strftime("%s")
        )
        self.event["not_before"] = int(
            cert.get_not_before().get_datetime().strftime("%s")
        )
        if self.event["not_after"] < time.time():
            self.event["expired"] = True
        else:
            self.event["expired"] = False
