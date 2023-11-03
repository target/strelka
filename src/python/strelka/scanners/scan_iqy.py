# Description #
# This scanner is looking for iqy files used with excel.
#
# author: Tasha Taylor
# date: 10/30/2023

import re

from strelka import strelka


class ScanIqy(strelka.Scanner):
    """
    Extract URLs from IQY files.

    IQY files, or Excel Web Query Internet Inquire files, are typically created from a VBA Web Query output.
    The following is a typical format:
        WEB
        1
        [URL]
        [optional parameters]
    Additional properties can be found at: https://learn.microsoft.com/en-us/office/vba/api/excel.querytable
    """

    def scan(self, data, file, options, expire_at):
        try:
            # Regular expression for detecting a URL-like pattern
            address_pattern = re.compile(
                r"\b(?:http|https|ftp|ftps|file|smb)://\S+|"
                r"\\{2}\w+\\(?:[\w$]+\\)*[\w$]+",
                re.IGNORECASE,
            )

            # Attempt UTF-8 decoding first, fall back to latin-1 if necessary
            try:
                data = data.decode("utf-8")
            except UnicodeDecodeError:
                data = data.decode("latin-1")

            # Split lines to review each record separately
            data_lines = data.splitlines()

            addresses = set()
            # For each line, check if the line matches the address pattern.
            # In a typical IQY file, the "WEB" keyword is at the beginning of the file,
            # and what follows is usually just one URL with optional additional parameters.
            # However, because we are iterating lines anyway, lets check for additional addresses anyway.
            for entry in data_lines[1:]:
                match = address_pattern.search(entry)
                if match:
                    address = match.group().strip()
                    if address:
                        addresses.add(address)

            # Evaluate if any addresses were found and assign the boolean result.
            self.event["address_found"] = bool(addresses)

            # Send all addresses to the IOC parser.
            self.add_iocs(list(addresses), self.type.url)

        except UnicodeDecodeError as e:
            self.flags.append(f"Unicode decoding error: {e}")
        except Exception as e:
            self.flags.append(f"Unexpected exception: {e}")
