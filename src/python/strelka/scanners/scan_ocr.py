import base64
import io
import os
import subprocess
import tempfile

import fitz
from PIL import Image

from strelka import strelka


class ScanOcr(strelka.Scanner):
    """Extracts optical text from image files and creates a thumbnail.

    This scanner extracts text from image files using OCR (Optical Character Recognition) and
    generates a base64-encoded thumbnail. It supports direct image files and converting PDFs
    to images for OCR.

    Options:
        extract_text: If True, extracted text is emitted as a child file. (default: False)
        split_words: If True, splits the OCR text into words and stores an array. (default: True)
        remove_formatting: If True, removes formatting characters (e.g., \r). Overridden by split_words. (default: True)
        tmp_directory: Directory for temporary files. (default: '/tmp/')
        pdf_to_png: If True, converts PDFs to PNG for OCR. (default: False)
        create_thumbnail: If True, creates a thumbnail for the image. (default: False)
        thumbnail_size: Size of the thumbnail to create. (default: (250, 250))
    """

    def scan(self, data, file, options, expire_at):
        extract_text = options.get("extract_text", False)
        remove_formatting = options.get("remove_formatting", True)
        tmp_directory = options.get("tmp_directory", "/tmp/")
        pdf_to_png = options.get("pdf_to_png", False)
        create_thumbnail = options.get("create_thumbnail", False)
        thumbnail_size = options.get("thumbnail_size", (250, 250))

        # Convert PDF to PNG if required.
        if pdf_to_png and "application/pdf" in file.flavors.get("mime", []):
            try:
                reader = fitz.open(stream=data, filetype="pdf")
                if reader.is_encrypted:
                    return
                data = reader.get_page_pixmap(0).tobytes("png")
            except Exception as e:
                self.flags.append(
                    f"{self.__class__.__name__}: image_pdf_error: {str(e)[:50]}"
                )

        # Create a thumbnail from the image.
        # Stores as a base64 value in the key: base64_thumbnail
        if create_thumbnail:
            try:
                image = Image.open(io.BytesIO(data))
                image.thumbnail(thumbnail_size, Image.Resampling.BILINEAR)
                buffered = io.BytesIO()
                image.save(buffered, format="WEBP", quality=70, optimize=True)
                base64_image = base64.b64encode(buffered.getvalue()).decode("utf-8")
                self.event["base64_thumbnail"] = base64_image
            except Exception as e:
                self.flags.append(
                    f"{self.__class__.__name__}: image_thumbnail_error: {str(e)[:50]}"
                )
        # Perform OCR on the image data.
        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_tess:
                try:
                    tess_txt_name = f"{tmp_tess.name}.txt"
                    subprocess.run(
                        ["tesseract", tmp_data.name, tmp_tess.name],
                        capture_output=True,
                        check=True,
                    )

                    with open(tess_txt_name, "rb") as tess_txt:
                        ocr_file = tess_txt.read()
                        if ocr_file:
                            self.event["text"] = ocr_file.split()
                            if remove_formatting:
                                self.event["string_text"] = (
                                    ocr_file.replace(b"\r", b"")
                                    .replace(b"\n", b"")
                                    .replace(b"\f", b"")
                                )
                            else:
                                self.event["string_text"] = ocr_file
                        if extract_text:
                            # Send extracted file back to Strelka
                            self.emit_file(ocr_file, name="text")

                    os.remove(tess_txt_name)

                except subprocess.CalledProcessError as e:
                    self.flags.append(
                        f"{self.__class__.__name__}: tesseract_process_error: {str(e)[:50]}"
                    )
                    raise strelka.ScannerException(e.stderr)
