from datetime import datetime

from OpenSSL import crypto

from strelka import core


class ScanX509(core.StrelkaScanner):
    """Collects metadata from x509 and CRL files.

    x509 extensions require cleanup and may be improperly formatted.

    Options:
        type: String that determines the type of x509 certificate being
            scanned. Must be either 'der' or 'pem'.
            Defaults to empty string.
    """
    def scan(self, data, file_object, options):
        type = options.get('type', '')

        crypto_filetype = None
        if type == 'der':
            crypto_filetype = crypto.FILETYPE_ASN1
        elif type == 'pem':
            crypto_filetype = crypto.FILETYPE_PEM

        certificate = None
        try:
            if crypto_filetype is not None:
                certificate = crypto.load_certificate(
                    crypto_filetype,
                    data,
                )

        except crypto.Error:
            self.flags.add(f'{self.scanner_name}::load_certificate_error')

        if certificate is not None:
            self.metadata['subjectString'] = b', '.join([b'='.join(sc) for sc in certificate.get_subject().get_components()])
            self.metadata['issuerString'] = b', '.join([b'='.join(ic) for ic in certificate.get_issuer().get_components()])
            self.metadata['notAfter'] = datetime.strptime(certificate.get_notAfter().decode(), '%Y%m%d%H%M%SZ').isoformat(timespec='seconds')
            self.metadata['notBefore'] = datetime.strptime(certificate.get_notBefore().decode(), '%Y%m%d%H%M%SZ').isoformat(timespec='seconds')
            self.metadata['serialNumber'] = str(certificate.get_serial_number())
            self.metadata['signatureAlgorithm'] = certificate.get_signature_algorithm()
            self.metadata['version'] = certificate.get_version()
            self.metadata['expired'] = certificate.has_expired()
            self.metadata['subjectNameHash'] = str(certificate.subject_name_hash())

            self.metadata.setdefault('extensions', [])
            for index in range(certificate.get_extension_count()):
                try:
                    name = certificate.get_extension(index=index).get_short_name().decode()
                    if name not in ['UNDEF']:
                        value = certificate.get_extension(index=index).__str__()
                        if name in ['extendedKeyUsage', 'keyUsage']:
                            value = value.split(', ')
                        if name == 'crlDistributionPoints':
                            value = value.replace('Full Name:', '')
                        if name == 'subjectAltName':
                            value = value.replace('DNS:', '')
                        if name in ['crlDistributionPoints', 'authorityInfoAccess']:
                            value = [ev.strip() for ev in value.split('\n') if ev]

                        extension_entry = {'name': name, 'value': value}
                        if extension_entry not in self.metadata['extensions']:
                            self.metadata['extensions'].append(extension_entry)

                except crypto.Error:
                    self.flags.add(f'{self.scanner_name}::extension_{name.lower()}')

        else:
            crl = None
            try:
                if crypto_filetype is not None:
                    crl = crypto.load_crl(crypto_filetype, data)
                    self.flags.add(f'{self.scanner_name}::crl')

            except crypto.Error:
                self.flags.add(f'{self.scanner_name}::load_crl_error')

            if crl is not None:
                self.metadata['issuerString'] = b', '.join([b'='.join(ic) for ic in crl.get_issuer().get_components()])

                revoked = crl.get_revoked()
                if revoked:
                    self.metadata['total'] = {'revoked': len(revoked)}
                    self.metadata.setdefault('revoked', [])
                    for r in revoked:
                        revoked_entry = {
                            'reason': r.get_reason(),
                            'date': datetime.strptime(r.get_rev_date().decode(), '%Y%m%d%H%M%SZ').isoformat(timespec='seconds'),
                            'serialNumber': r.get_serial(),
                        }

                        if revoked_entry not in self.metadata['revoked']:
                            self.metadata['revoked'].append(revoked_entry)
