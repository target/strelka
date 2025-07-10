import base64
import io
import os
import subprocess
import tempfile

import pymupdf
from PIL import Image

from strelka import strelka


class ScanOcr(strelka.Scanner):
    """
    Extracts optical text from image files and (optionally) generates a thumbnail using OCR
    (Optical Character Recognition).

    This scanner processes image files and PDFs (if enabled), extracting text content via OCR. It can also generate a
    thumbnail for the image. This is useful for analyzing document images and scanned PDFs to extract textual data for
    further analysis.

    Scanner Type: Collection

    Attributes:
        event (dict): Stores extracted text and thumbnail data during the scan.

    Options:
        - extract_text (bool): If True, extracted text is emitted as a child file.
        - split_words (bool): If True, splits the OCR text into words and stores an array.
        - remove_formatting (bool): If True, removes formatting characters (e.g., \r). Overridden by split_words.
        - tmp_directory (str): Directory for temporary files.
        - render_dpi (int): Resolution of the output image in dots per inch (DPI) when converting PDFs to images.
        - render_format (str): Format of the output image when converting PDFs to images for OCR.
        - create_thumbnail (bool): If True, creates a thumbnail for the image.
        - thumbnail_size (tuple): Size of the thumbnail to create.

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Text Extraction**
            - Extract text from images and scanned documents for content analysis and pattern matching.
        - **Thumbnail Generation**
            - Generate a visual summary of the document for quick reference.

    ## Known Limitations
    !!! warning "Known Limitations"
        - **Image Quality Dependence**
            - OCR accuracy heavily depends on the quality and clarity of the input image.
        - **Issues Observed From Image Corruption**
            - Images observed to be corrupt from the source or processing will throw errors and fail to scan.

    ## To Do
    !!! question "To Do"
        - Enhance PDF handling to support OCR on all pages.

    ## Contributors
    !!! example "Contributors"
        - [Josh Liburdi](https://github.com/jshlbrd)
        - [Ryan O'Horo](https://github.com/ryanohoro)
        - [Paul Hutelmyer](https://github.com/phutelmyer)
        - [Sara Kalupa](https://github.com/skalupa)
    """

    def scan(self, data, file, options, expire_at):
        """
        Scans the given data for text using OCR and optionally generates a thumbnail.

        The function handles image files directly and can convert PDFs to images if enabled. Extracted text and
        generated thumbnails are stored in the event dictionary.

        Args:
            data (bytes): Data of the file being scanned.
            file (strelka.File): File object being scanned.
            options (dict): Options for the scanner.
            expire_at (datetime): Expiration time of the scan result.
        """
        extract_text = options.get("extract_text", False)
        # remove_formatting = options.get("remove_formatting", True)
        tmp_directory = options.get("tmp_directory", "/tmp/")
        render_dpi = options.get("render_dpi", 300)
        render_format = options.get("render_format", "png")
        create_thumbnail = options.get("create_thumbnail", False)
        thumbnail_size = options.get("thumbnail_size", (250, 250))

        # Opportunistically convert PDF to image
        try:
            reader = pymupdf.open(stream=data)
            if reader.is_encrypted:
                return

            pixmap = reader.get_page_pixmap(0, dpi=render_dpi)

            self.event["render"] = {}
            self.event["render"]["source"] = "pdf"
            self.event["render"]["width"] = pixmap.width
            self.event["render"]["height"] = pixmap.height
            self.event["render"]["dpi"] = pixmap.xres
            self.event["render"]["format"] = render_format

            data = pixmap.tobytes(render_format)

        except Exception as e:
            # If the file was likely a PDF, but failed to convert, append flag
            if "application/pdf" in file.flavors.get("mime", []):
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
            finally:
                image.close()

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
                        if extract_text:
                            # Send extracted file back to Strelka
                            self.emit_file(ocr_file, name="text")

                    os.remove(tess_txt_name)

                except subprocess.CalledProcessError as e:
                    self.flags.append(
                        f"{self.__class__.__name__}: tesseract_process_error: {str(e)}"
                    )
                finally:
                    # Ensure tempfile is closed even after error is thrown
                    tmp_data.close()
                    tmp_tess.close()
