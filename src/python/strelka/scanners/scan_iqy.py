import re

from strelka import strelka


class ScanIqy(strelka.Scanner):
    """
    Strelka scanner for extracting URLs from IQY (Excel Web Query Internet Inquire) files.

    IQY files are typically used to import data into Excel from the web. They often contain URLs
    that specify the data source. This scanner aims to extract these URLs and process them for IOCs.

    The following is a typical format of an IQY file:
    WEB
    1
    [URL]
    [optional parameters]

    Reference for IQY file format: https://learn.microsoft.com/en-us/office/vba/api/excel.querytable
    """

    def scan(self, data, file, options, expire_at):
        """
        Processes the provided IQY data to extract URLs.

        Attempts to decode the data and applies a regex pattern to identify and extract URLs.
        Extracted URLs are added to the scanner's IOC list.

        Args:
            data (bytes): Data associated with the IQY file to be scanned.
            file (strelka.File): File object associated with the data.
            options (dict): Options to be applied during the scan.
            expire_at (int): Expiration timestamp for extracted files.
        """
        try:
            # Compile regex pattern for URL detection
            address_pattern = re.compile(
                r"\b(?:http|https|ftp|ftps|file|smb)://\S+|"
                r"\\{2}\w+\\(?:[\w$]+\\)*[\w$]+",
                re.IGNORECASE,
            )

            # Attempt to decode the data
            try:
                decoded_data = data.decode("utf-8")
            except UnicodeDecodeError:
                decoded_data = data.decode("latin-1")

            # Extract addresses from the data
            addresses = set(
                match.group().strip()
                for line in decoded_data.splitlines()
                if (match := address_pattern.search(line))
            )

            # Add extracted URLs to the scanner's IOC list
            if addresses:
                self.event["address_found"] = True
                self.add_iocs(list(addresses))
            else:
                self.event["address_found"] = False

        except UnicodeDecodeError as e:
            self.flags.append(f"Unicode decoding error: {e}")
        except Exception as e:
            self.flags.append(f"Unexpected exception: {e}")
