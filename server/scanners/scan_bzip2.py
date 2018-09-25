import bz2
import io

from server import objects


class ScanBzip2(objects.StrelkaScanner):
    """Decompresses bzip2 files."""
    def scan(self, file_object, options):
        with io.BytesIO(file_object.data) as bzip2_object:
            with bz2.BZ2File(filename=bzip2_object) as bzip2_file:
                try:
                    decompressed_file = bzip2_file.read()
                    decompressed_size = len(decompressed_file)
                    child_filename = f"{self.scanner_name}::size_{decompressed_size}"
                    self.metadata["decompressedSize"] = decompressed_size
                    child_fo = objects.StrelkaFile(data=decompressed_file,
                                                   filename=child_filename,
                                                   depth=file_object.depth + 1,
                                                   parent_uid=file_object.uid,
                                                   root_uid=file_object.root_uid,
                                                   parent_hash=file_object.hash,
                                                   root_hash=file_object.root_hash,
                                                   source=self.scanner_name)
                    self.children.append(child_fo)

                except OSError:
                    file_object.flags.append(f"{self.scanner_name}::os_error")
