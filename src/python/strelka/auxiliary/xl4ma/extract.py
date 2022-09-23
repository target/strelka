# Authors: Ryan Borre

import re
import socket
import struct
from urllib.parse import urlparse


def iocs(excel_doc_decoded):
    extracted = set()
    for decoded in excel_doc_decoded:
        if url := re.findall('(https?://[A-Za-z0-9-._]+/[A-Za-z0-9-._~:/?#\[\]@!$&\'\(\)*+,;%=]+[^,\s\)])', decoded, flags=re.IGNORECASE):
            scheme, netloc, path, params, query, fragment = urlparse(url[0])
            if netloc.startswith('0x'):
                netloc = socket.inet_ntoa(struct.pack(">L", int(netloc, 16)))
            if netloc.startswith('0o'):
                netloc = socket.inet_ntoa(struct.pack(">L", int(netloc, 8)))
            extracted.add(f"{scheme}://{netloc}{path}")

    return list(sorted(extracted))
