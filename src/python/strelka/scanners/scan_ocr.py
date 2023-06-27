import fitz
import os
import subprocess
import tempfile

from strelka import strelka


class ScanOcr(strelka.Scanner):
    """Collects metadata and extracts optical text from image files.

    Options:
        extract_text: Boolean that determines if optical text should be
            extracted as a child file.
            Defaults to False.
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """

    def scan(self, data, file, options, expire_at):
        extract_text = options.get("extract_text", False)
        split_words = options.get("split_words", True)
        tmp_directory = options.get("tmp_directory", "/tmp/")
        pdf_to_png = options.get('pdf_to_png', False)

        if pdf_to_png and 'application/pdf' in file.flavors.get('mime', []):
            doc = fitz.open(stream=data, filetype='pdf')
            data = doc.get_page_pixmap(0).tobytes('png')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_tess:
                try:
                    tess_txt_name = f"{tmp_tess.name}.txt"

                    completed_process = subprocess.run(
                        ["tesseract", tmp_data.name, tmp_tess.name],
                        capture_output=True,
                        check=True,
                    )

                    _ = completed_process

                    with open(tess_txt_name, "rb") as tess_txt:
                        ocr_file = tess_txt.read()

                        if ocr_file:
                            if split_words:
                                self.event["text"] = ocr_file.split()
                            else:
                                self.event["text"] = (
                                    ocr_file.replace(b"\r", b"")
                                    .replace(b"\n", b"")
                                    .replace(b"\f", b"")
                                )

                            if extract_text:
                                # Send extracted file back to Strelka
                                self.emit_file(ocr_file, name="text")

                    os.remove(tess_txt_name)

                except subprocess.CalledProcessError as e:
                    self.flags.append("tesseract_process_error")
                    raise strelka.ScannerException(e.stderr)
