import gzip
import io

from server import lib


class ScanGzip(lib.StrelkaScanner):
    """Decompresses gzip files."""
    def scan(self, file_object, options):
        with io.BytesIO(file_object.data) as gzip_object:
            with gzip.GzipFile(fileobj=gzip_object) as gzip_file:
                decompressed_file = gzip_file.read()
                decompressed_size = len(decompressed_file)
                self.metadata['decompressedSize'] = decompressed_size
                child_filename = f'{self.scanner_name}::size_{decompressed_size}'
                child_fo = lib.StrelkaFile(data=decompressed_file,
                                           filename=child_filename,
                                           depth=file_object.depth + 1,
                                           parent_uid=file_object.uid,
                                           root_uid=file_object.root_uid,
                                           parent_hash=file_object.hash,
                                           root_hash=file_object.root_hash,
                                           source=self.scanner_name)
                self.children.append(child_fo)
