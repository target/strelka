import re

import olefile
import oletools

from server import objects


class ScanOle(objects.StrelkaScanner):
    """Extracts files from OLECF files."""
    def scan(self, file_object, options):
        self.metadata["total"] = {"streams": 0, "extracted": 0}

        try:
            ole = olefile.OleFileIO(file_object.data)
            ole_streams = ole.listdir(streams=True)
            self.metadata["total"]["streams"] = len(ole_streams)
            for stream in ole_streams:
                file = ole.openstream(stream)
                child_file = file.read()
                joined_stream = "_".join(stream)
                child_filename = f"{self.scanner_name}::{joined_stream}"
                child_filename = re.sub(r"[\x00-\x1F]", "", child_filename)
                if child_filename.endswith("Ole10Native"):
                    native_stream = oletools.oleobj.OleNativeStream(bindata=child_file)
                    if native_stream.filename:
                        child_filename = child_filename + f"_{str(native_stream.filename)}"
                    else:
                        child_filename = child_filename + "_native_data"
                    child_fo = objects.StrelkaFile(data=native_stream.data,
                                                   filename=child_filename,
                                                   depth=file_object.depth + 1,
                                                   parent_uid=file_object.uid,
                                                   root_uid=file_object.root_uid,
                                                   parent_hash=file_object.hash,
                                                   root_hash=file_object.root_hash,
                                                   source=self.scanner_name)
                else:
                    child_fo = objects.StrelkaFile(data=child_file,
                                                   filename=child_filename,
                                                   depth=file_object.depth + 1,
                                                   root_uid=file_object.root_uid,
                                                   parent_hash=file_object.hash,
                                                   root_hash=file_object.root_hash,
                                                   source=self.scanner_name)
                self.children.append(child_fo)
                self.metadata["total"]["extracted"] += 1
            ole.close()

        except OSError:
            file_object.flags.append(f"{self.scanner_name}::os_error")
