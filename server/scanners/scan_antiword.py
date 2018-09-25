import subprocess
import tempfile

from server import objects


class ScanAntiword(objects.StrelkaScanner):
    """Extracts text from MS Word document files.

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

            (stdout,
             stderr) = subprocess.Popen(["antiword",
                                         strelka_filename],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL).communicate()
            if stdout:
                child_fo = objects.StrelkaFile(data=stdout,
                                               filename=f"{self.scanner_name}::text",
                                               depth=file_object.depth + 1,
                                               parent_uid=file_object.uid,
                                               root_uid=file_object.root_uid,
                                               parent_hash=file_object.hash,
                                               root_hash=file_object.root_hash,
                                               source=self.scanner_name)
                self.children.append(child_fo)
