import os
import subprocess
import tempfile

from server import objects


class ScanUpx(objects.StrelkaScanner):
    """Decompresses UPX packed files.

    Options:
        tempfile_directory: Location where tempfile writes temporary files.
            Defaults to "/tmp/".
    """
    def scan(self, file_object, options):
        tempfile_directory = options.get("tempfile_directory", "/tmp/")

        with tempfile.NamedTemporaryFile(dir=tempfile_directory) as strelka_file:
            strelka_filename = strelka_file.name
            strelka_file.write(file_object.data)
            strelka_file.flush()

            upx_filename = strelka_filename + "_upx"
            upx_returncode = subprocess.call(["upx", "-d",
                                              strelka_filename, "-o",
                                              upx_filename],
                                             stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL)
            if upx_returncode == 0:
                with open(upx_filename, "rb") as upx_fin:
                    upx_file = upx_fin.read()
                    upx_size = len(upx_file)
                    if upx_size > file_object.size:
                        child_filename = f"{self.scanner_name}::size_{upx_size}"
                        child_fo = objects.StrelkaFile(data=upx_file,
                                                       filename=child_filename,
                                                       depth=file_object.depth + 1,
                                                       parent_uid=file_object.uid,
                                                       root_uid=file_object.root_uid,
                                                       parent_hash=file_object.hash,
                                                       root_hash=file_object.root_hash,
                                                       source=self.scanner_name)
                        self.children.append(child_fo)
                os.remove(upx_filename)
            else:
                file_object.flags.append(f"{self.scanner_name}::return_code_{upx_returncode}")
