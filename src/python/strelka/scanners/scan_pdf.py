import io
import re
from collections import Counter
from datetime import datetime, timezone

import fitz

from strelka import strelka

# Suppress PyMuPDF warnings
fitz.TOOLS.mupdf_display_errors(False)

# Regular expression for extracting phone numbers from PDFs
PHONE_NUMBERS_REGEX = re.compile(
    r"[+]?(?:\d{1,2})?\s?\(?\d{3}\)?[\s.-][\n]?\d{3}[\s.-][\n]?\d{2,4}?-?\d{2,4}?",
    flags=re.IGNORECASE,
)


class ScanPdf(strelka.Scanner):
    """
    Extracts metadata, embedded files, images, and text from PDF files.

    This scanner utilizes PyMuPDF to parse PDF files, extracting various types of data,
    including metadata, embedded files, images, and textual content. Phone numbers and
    URLs within the document are also extracted and reported.
    """

    @staticmethod
    def _convert_timestamp(timestamp):
        """
        Converts a PDF timestamp string to an ISO 8601 formatted string.

        PDF timestamps are typically in the 'D:%Y%m%d%H%M%S%z' format. This function
        converts them to a more standard ISO 8601 format.

        Args:
            timestamp: A string representing the timestamp in PDF format.

        Returns:
            An ISO 8601 formatted timestamp string, or None if conversion fails.
        """
        try:
            return (
                datetime.strptime(timestamp.replace("'", ""), "D:%Y%m%d%H%M%S%z")
                .astimezone(timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        except Exception:
            return None

    def scan(self, data, file, options, expire_at):
        """
        Performs the scanning process on the provided data.

        The function opens the PDF using PyMuPDF and extracts metadata, embedded files,
        images, and text. Phone numbers and URLs are also extracted using regular expressions.

        Args:
            data: Data of the file to be scanned.
            file: The File object associated with the data.
            options: Dictionary of scanner-specific options.
            expire_at: Expiration time of the scan.
        """
        # Set maximum XREF objects to be collected (default: 250)
        max_objects = options.get("max_objects", 250)

        try:
            with io.BytesIO(data) as pdf_io:
                reader = fitz.open(stream=pdf_io, filetype="pdf")

            # Collect Metadata
            self.event["dirty"] = reader.is_dirty
            self.event["encrypted"] = reader.is_encrypted
            self.event["language"] = reader.language
            self.event["needs_pass"] = reader.needs_pass
            self.event["old_xrefs"] = reader.has_old_style_xrefs
            self.event["pages"] = reader.page_count
            self.event["repaired"] = reader.is_repaired
            self.event["xrefs"] = reader.xref_length() - 1

            if reader.is_encrypted:
                return

            # Set Default Variables
            self.event["images"] = 0
            self.event["lines"] = 0
            self.event["links"] = []
            self.event["words"] = 0
            self.event.setdefault("xref_object", list())
            keys = list()

            self.event["author"] = reader.metadata["author"]
            self.event["creator"] = reader.metadata["creator"]
            self.event["creation_date"] = self._convert_timestamp(
                reader.metadata["creationDate"]
            )
            self.event["embedded_files"] = {
                "count": reader.embfile_count(),
                "names": reader.embfile_names(),
            }
            self.event["format"] = reader.metadata["format"]
            self.event["keywords"] = reader.metadata["keywords"]
            self.event["modify_date"] = self._convert_timestamp(
                reader.metadata["modDate"]
            )
            self.event["producer"] = reader.metadata["producer"]
            self.event["subject"] = reader.metadata["subject"]
            self.event["title"] = reader.metadata["title"]

            # Collect Phones Numbers
            phones = []
            for i in range(self.event["pages"]):
                phones.extend(
                    [
                        re.sub("[^0-9]", "", x)
                        for x in re.findall(
                            PHONE_NUMBERS_REGEX,
                            reader.get_page_text(i).replace("\t", " "),
                        )
                    ]
                )
            self.event["phones"] = list(set(phones))

            # iterate through xref objects. Collect, count, and extract objects
            self.event["xref_object"] = list()
            for xref in range(1, reader.xref_length()):
                xref_object = reader.xref_object(xref, compressed=True)
                if xref_object not in self.event["xref_object"]:
                    self.event["xref_object"].append(xref_object)
                for obj in options.get("objects", []):
                    pattern = f"/{obj}"
                    if pattern in xref_object:
                        keys.append(obj.lower())
                # Extract urls from xref
                self.event["links"].extend(
                    re.findall(r"https?://[^\s)>]+", xref_object)
                )
            self.event["objects"] = dict(Counter(keys))

            # Convert unique xref_object set back to list
            self.event["xref_object"] = list(
                set(self.event["xref_object"][:max_objects])
            )

            # Submit embedded files to strelka
            try:
                for i in range(reader.embfile_count()):
                    props = reader.embfile_info(i)

                    # Send extracted file back to Strelka
                    self.emit_file(reader.embfile_get(i), name=props["filename"])

            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                self.flags.append(f"pdf_embedded_processing_error: {str(e)[:50]}")

            # Submit extracted images to strelka
            try:
                for i in range(len(reader)):
                    for img in reader.get_page_images(i):
                        self.event["images"] += 1
                        pix = fitz.Pixmap(reader, img[0])

                        # Send extracted file back to Strelka
                        self.emit_file(pix.tobytes(), name="image")

            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                self.flags.append(f"pdf_image_processing_error: {str(e)[:50]}")

            # Parse data from each page
            try:
                text = ""
                for page in reader:
                    self.event["lines"] += len(page.get_text().split("\n"))
                    self.event["words"] += len(
                        list(filter(None, page.get_text().split(" ")))
                    )
                    # Extract links
                    for link in page.get_links():
                        self.event["links"].append(link.get("uri"))

                    text += page.get_text()

                    # Extract urls from text
                    self.event["links"].extend(re.findall(r"https?://[^\s)>]+", text))

                # If links found, remove all duplicates and submit as IOCs.
                # Deduplicate the links
                if self.event["links"]:
                    self.event["links"] = list(set(filter(None, self.event["links"])))

                    # Submit all links to the IOCs pipeline.
                    self.add_iocs(self.event["links"])

                # Send extracted file back to Strelka
                self.emit_file(text.encode("utf-8"), name="text")

            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                self.flags.append(f"pdf_page_processing_error: {str(e)[:50]}")
        except strelka.ScannerTimeout:
            raise
        except Exception as e:
            self.flags.append(f"pdf_load_error: {str(e)[:50]}")
