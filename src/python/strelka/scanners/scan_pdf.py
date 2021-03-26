import io
import fitz

from strelka import strelka

# Hide PyMuPDF Warnings
fitz.TOOLS.mupdf_display_errors(value=False)


class ScanPdf(strelka.Scanner):
    """Collects metadata and extracts files from PDF files.

    Options:
        extract_text: Boolean that determines if document text should be
            extracted as a child file.
            Defaults to False.
        limit: Maximum number of files to extract.
            Defaults to 2000.
    """
    def scan(self, data, file, options, expire_at):
        extract_text = options.get('extract_text', False)
        file_limit = options.get('limit', 2000)

        self.event['total'] = {'objects': 0, 'extracted': 0}
        extracted_objects = set()

        try:
            with io.BytesIO(data) as pdf_io:

                # Open file as with PyMuPDF as file object
                reader = fitz.open(stream=pdf_io, filetype="pdf")

                # Get length of xrefs to be used in xref / annotation iteration
                xreflen = reader.xref_length()

                # Iterate through xrefs and collect annotations
                i = 0
                for xref in range(1, xreflen):

                    # PDF Annotation Flags
                    xref_object = reader.xref_object(i, compressed=False)
                    if any(obj in xref_object for obj in ["/AA", "/OpenAction"]):
                        self.flags.append('auto_action')
                    if any(obj in xref_object for obj in ["/JS", "/JavaScript"]):
                        self.flags.append('javascript_embedded')

                    # PDF Object Resubmission
                    # If xref is a stream, add that object back into the analysis pipeline
                    if reader.is_stream(xref):
                        try:
                            if xref not in extracted_objects:
                                extract_file = strelka.File(
                                    name=f'object_{xref}',
                                    source=self.name,
                                )

                                for c in strelka.chunk_string(reader.xref_stream(xref)):
                                    self.upload_to_coordinator(
                                        extract_file.pointer,
                                        c,
                                        expire_at,
                                    )

                                self.files.append(extract_file)
                                self.event['total']['extracted'] += 1
                                extracted_objects.add(xref)

                        except Exception as e:
                            self.flags.append(f'stream exception {e}')
                    i += 1

                # Iterate through pages and collect links and text
                if extract_text:
                    extracted_text = ""

                for page in reader:

                    # PDF Link Extraction
                    self.event.setdefault('annotated_uris', [])
                    links = page.get_links()
                    if links:
                        for link in links:
                            if 'uri' in link:
                                self.event['annotated_uris'].append(link["uri"])
                    if extract_text:
                        extracted_text += page.getText()

                # PDF Text Extraction
                # Caution: Will increase time and object storage size
                if extract_text:
                    extract_file = strelka.File(
                        name='text',
                        source=self.name,
                    )
                    for c in strelka.chunk_string(extracted_text):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )
                    self.files.append(extract_file)
                    self.flags.append('extracted_text')

        except Exception as e:
            self.flags.append(f'general exception {e}')