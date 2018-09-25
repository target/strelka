import os
import subprocess
import tempfile

from server import objects


class ScanOcr(objects.StrelkaScanner):
    """Collects metadata and extracts optical text from image files.

    Options:
        extract_text: Boolean that determines if optical text should be
            extracted as a child file.
            Defaults to False.
        tempfile_directory: Location where tempfile writes temporary files.
            Defaults to "/tmp/".
    """
    def scan(self, file_object, options):
        extract_text = options.get("extract_text", False)
        tempfile_directory = options.get("tempfile_directory", "/tmp/")

        with tempfile.NamedTemporaryFile(dir=tempfile_directory) as strelka_file:
            strelka_filename = strelka_file.name
            strelka_file.write(file_object.data)
            strelka_file.flush()

            with tempfile.NamedTemporaryFile(dir=tempfile_directory) as tesseract_file:
                tesseract_filename = tesseract_file.name
                tesseract_txt_filename = f"{tesseract_filename}.txt"
                tesseract_returncode = subprocess.call(["tesseract",
                                                        strelka_filename,
                                                        tesseract_filename],
                                                       stdout=subprocess.DEVNULL,
                                                       stderr=subprocess.DEVNULL)
                if tesseract_returncode == 0:
                    with open(tesseract_txt_filename, "rb") as tesseract_txt:
                        ocr_file = tesseract_txt.read()
                        if ocr_file:
                            self.metadata["text"] = ocr_file.split()
                            if extract_text:
                                child_filename = f"{self.scanner_name}::text"
                                child_fo = objects.StrelkaFile(data=ocr_file,
                                                               filename=child_filename,
                                                               depth=file_object.depth + 1,
                                                               parent_uid=file_object.uid,
                                                               root_uid=file_object.root_uid,
                                                               parent_hash=file_object.hash,
                                                               root_hash=file_object.root_hash,
                                                               source=self.scanner_name)
                                self.children.append(child_fo)
                else:
                    file_object.flags.append(f"{self.scanner_name}::return_code_{tesseract_returncode}")
                os.remove(tesseract_txt_filename)
