import base64
import binascii
import io
import re

from server import objects


class ScanBase64Pe(objects.StrelkaScanner):
    """Decode base64 encoded PE files."""
    def scan(self, file_object, options):
        Base64RegEx = re.compile('TV(oAAA|pBUl|pQAA|qAAA|qQAA|roAA)[A-Za-z0-9/+]{248,}[\=]{0,2}')
        UrlSafeRegEx = re.compile('TV(oAAA|pBUl|pQAA|qAAA|qQAA|roAA)[A-Za-z0-9_-]{248,}[\=]{0,2}')
        base64pe_string = Base64RegEx.search(str(file_object.data))
        if base64pe_string:
            try:
                decoded_file = base64.b64decode(base64pe_string.group(0))        
            except binascii.Error:
                file_object.flags.append(f"{self.scanner_name}::binascii_error_{object_id}")
        urlsafe_string = UrlSafeRegEx.search(str(file_object.data))
        if urlsafe_string:
            try:
                decoded_file = base64.urlsafe_b64decode(urlsafe_string.group(0))
            except binascii.Error:
                file_object.flags.append(f"{self.scanner_name}::binascii_error_{object_id}")
        if decoded_file:
            decoded_size = len(decoded_file)
            self.metadata["decodedSize"] = decoded_size
            child_filename = f"{self.scanner_name}::size_{decoded_size}"
            child_fo = objects.StrelkaFile(data=decoded_file,
                                           filename=child_filename,
                                           depth=file_object.depth + 1,
                                           parent_uid=file_object.uid,
                                           root_uid=file_object.root_uid,
                                           parent_hash=file_object.hash,
                                           root_hash=file_object.root_hash,
                                           source=self.scanner_name)
            self.children.append(child_fo)
