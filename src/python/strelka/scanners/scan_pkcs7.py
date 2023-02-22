import tempfile

from M2Crypto import SMIME, X509

from strelka import strelka


class ScanPkcs7(strelka.Scanner):
    """Extracts files from PKCS7 certificate files."""

    def scan(self, data, file, options, expire_at):
        # Set the temporary directory for storing data. The default is "/tmp/".
        tmp_directory = options.get("tmp_directory", "/tmp/")

        # Initialize the "total" field in the event object with the number of certificates and extracted files.
        self.event["total"] = {"certificates": 0, "extracted": 0}

        try:
            # Needs a file to load data, not a buffer.
            # Try to create a temporary file in the specified temporary directory.
            with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
                tmp_data.write(data)
                tmp_data.flush()

                # Try to load the PKCS7 key file.
                try:
                    if data[:1] == b"0":
                        pkcs7 = SMIME.load_pkcs7_der(tmp_data.name)
                    else:
                        pkcs7 = SMIME.load_pkcs7(tmp_data.name)
                except SMIME.SMIME_Error:
                    self.flags.append(
                        f"{self.__class__.__name__} Exception:  Error loading PKCS7 key file with SMIME error."
                    )
                    return
                except Exception as e:
                    self.flags.append(
                        f"{self.__class__.__name__} Exception: {str(e)[:50]}"
                    )
                    return

                # Try to get the signers from the PKCS7 file.
                try:
                    certs = pkcs7.get0_signers(X509.X509_Stack())
                except X509.X509Error:
                    self.flags.append(
                        f"{self.__class__.__name__} Exception:  Error collecting PKCS7 signers."
                    )
                    return
                except Exception as e:
                    self.flags.append(
                        f"{self.__class__.__name__} Exception: {str(e)[:50]}"
                    )
                    return

                # If there are signers in the PKCS7 file, process them.
                if certs:
                    self.event["total"]["certificates"] = len(certs)
                    for cert in certs:
                        try:
                            self.emit_file(
                                cert.as_der(), name=f"sn_{cert.get_serial_number()}"
                            )
                        except Exception:
                            self.flags.append(
                                f"{self.__class__.__name__} Exception:  Error processing PKCS7 signers."
                            )
                            return
                        self.event["total"]["extracted"] += 1
        except tempfile.NamedTemporaryFile:
            self.flags.append(
                f"{self.__class__.__name__} Exception: Error creating temporary file for PKCS7 file."
            )
        except Exception as e:
            self.flags.append(f"{self.__class__.__name__} Exception: {str(e)[:50]}")
