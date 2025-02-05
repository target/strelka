import io
import sys
import traceback

import fitz

from strelka import strelka


class ScanPdf(strelka.Scanner):
    """Collects metadata and extracts files from PDF files.

    Options:
        extract_text: Boolean that determines if document text should be
            extracted as a child file.
            Defaults to False.
        limit: Maximum number of files to extract.
            Defaults to 2000.
    """
    def init(self):
        fitz.TOOLS.mupdf_display_errors(False)

    def scan(self, data, file, options, expire_at):
        extract_text = options.get("extract_text", False)
        file_limit = options.get("limit", 2000)

        self.event["total"] = {"objects": 0, "extracted": 0}
        extracted_objects = set()

        pdf_to_png = options.get('pdf_to_png', False)

        try:
            if pdf_to_png:
                doc = fitz.open(stream=data, filetype='pdf')

                for i in range(0, min(3, doc.page_count)):
                    png_data = doc.get_page_pixmap(i, dpi=150).tobytes('png')

                    extract_file = strelka.File(
                        name=f"pdf_2_png_{i}",
                        source=self.name,
                    )
                    for c in strelka.chunk_string(png_data):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                    self.files.append(extract_file)
                    self.event['total']['extracted'] += 1
        except:
            self.flags.append('pdf_2_png_error')

        try:
            with io.BytesIO(data) as pdf_io:

                # Open file as with PyMuPDF as file object
                pdf_reader = fitz.open(stream=pdf_io, filetype="pdf")

                xreflen = 0
                no_object_extraction = options.get('no_object_extraction', False)

                # Get length of xrefs to be used in xref / annotation iteration
                if not no_object_extraction:
                    xreflen = pdf_reader.xref_length()

                # Iterate through xrefs and collect annotations
                i = 0
                for xref in range(1, xreflen):
                    # PDF Annotation Flags
                    xref_object = pdf_reader.xref_object(i, compressed=False)
                    if any(obj in xref_object for obj in ["/AA", "/OpenAction"]):
                        self.flags.append("auto_action")
                    if any(obj in xref_object for obj in ["/JS", "/JavaScript"]):
                        self.flags.append("javascript_embedded")

                    # PDF Object Resubmission
                    # If xref is a stream, add that object back into the analysis pipeline
                    if pdf_reader.xref_is_stream(xref):
                        try:
                            if xref not in extracted_objects:
                                extract_file = strelka.File(
                                    name=f"object_{xref}",
                                    source=self.name,
                                )

                                for c in strelka.chunk_string(pdf_reader.xref_stream(xref)):
                                    self.upload_to_coordinator(
                                        extract_file.pointer,
                                        c,
                                        expire_at,
                                    )

                                self.files.append(extract_file)
                                self.event["total"]["extracted"] += 1
                                extracted_objects.add(xref)

                        except Exception:
                            traceback.print_exc()
                            self.flags.append("stream_read_exception")

                    as_image = pdf_reader.extract_image(xref)
                    if as_image is not None and as_image is not False:
                        extract_file = strelka.File(
                            name=f"object_{xref}",
                            source=self.name,
                        )
                        for c in strelka.chunk_string(as_image["image"]):
                            self.upload_to_coordinator(
                                extract_file.pointer,
                                c,
                                expire_at,
                            )

                        self.files.append(extract_file)
                        self.event['total']['extracted'] += 1
                    i += 1

                # Iterate through pages and collect links and text
                if extract_text:
                    extracted_text = ""

                try:
                    for page in pdf_reader:
                        # PDF Link Extraction
                        self.event.setdefault("annotated_uris", [])
                        links = page.get_links()
                        if links:
                            for link in links:
                                if "uri" in link:
                                    self.event["annotated_uris"].append(link["uri"])
                        if extract_text and hasattr(page, "getText"):
                            extracted_text += page.getText()
                        if extract_text and hasattr(page, "get_text"):
                            extracted_text += page.get_text()

                    # PDF Text Extraction
                    # Caution: Will increase time and object storage size
                    if extract_text:
                        extract_file = strelka.File(
                            name="text",
                            source=self.name,
                        )
                        for c in strelka.chunk_string(extracted_text):
                            self.upload_to_coordinator(
                                extract_file.pointer,
                                c,
                                expire_at,
                            )
                        self.files.append(extract_file)
                        self.flags.append("extracted_text")
                except Exception:
                    traceback.print_exc()
                    self.flags.append("page_parsing_failure")
        except Exception:
            traceback.print_exc()
            self.flags.append("pdf_load_error")
