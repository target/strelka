"""
This module provides a scanner that extracts information from VSTO files.

It defines the following class:
    - ScanVsto: Scans VSTO files and extracts information like the name, assembly identity, dependencies,
                publisher, and certificate.

"""

import base64
import hashlib

import xmltodict

from strelka import strelka


class ScanVsto(strelka.Scanner):
    """
    Scanner class for extracting information from VSTO files.

    This class provides a `scan` method that extracts information from VSTO files, and stores it in the `event`
    dictionary attribute of the class.

    """

    def scan(self, data, file, options, expire_at):
        """
        Extracts information from the VSTO file.

        Args:
            data: The binary data of the VSTO file to be scanned.
            file: File associated with data.
            options: Any options passed in from the backend configuration file.
            expire_at: The expiry time for this scan.

        """
        try:
            # As Vsto is in an XML format, parse the XML data
            xml = xmltodict.parse(data)

            # Extract the VSTO name
            if props := xml.get("Properties"):
                for prop in props.get("property", []):
                    if prop["vt:lpwstr"].endswith("vstolocal"):
                        self.event["vsto"] = prop["vt:lpwstr"].split("|")[0]

            # Extract the assembly identity, dependencies, publisher, and certificate information
            if asm := xml.get("asmv1:assembly"):
                if asm.get("assemblyIdentity"):
                    self.event["identity"] = asm["assemblyIdentity"]["@name"]
                    self.event["dependency"] = {
                        "manifest": asm["dependency"]["dependentAssembly"]["@codebase"],
                        "name": asm["dependency"]["dependentAssembly"][
                            "assemblyIdentity"
                        ]["@name"],
                    }
                    self.event["publisher"] = asm["publisherIdentity"]["@name"]
                    self.event["certificate"] = {
                        "b64": asm["Signature"]["KeyInfo"]["msrel:RelData"][
                            "r:license"
                        ]["r:issuer"]["Signature"]["KeyInfo"]["X509Data"][
                            "X509Certificate"
                        ],
                        "md5": hashlib.md5(
                            base64.b64decode(
                                asm["Signature"]["KeyInfo"]["msrel:RelData"][
                                    "r:license"
                                ]["r:issuer"]["Signature"]["KeyInfo"]["X509Data"][
                                    "X509Certificate"
                                ]
                            )
                        ).hexdigest(),
                    }

        except Exception as e:
            print(e)
            self.flags.append(f"{self.__class__.__name__} Exception: {str(e)[:100]}")
