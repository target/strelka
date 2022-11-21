# https://pymupdf.readthedocs.io/en/latest/index.html
# https://www.osti.gov/servlets/purl/1030303

import datetime
import io
import re
import fitz
from collections import Counter
from strelka import strelka

# hide PyMuPDF warnings
fitz.TOOLS.mupdf_display_errors(False)
phone_numbers = re.compile(
    "\+?(?:\d{1,2})?\s?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{2,4}?\-?\d{2,4}?",
    flags=0,
)

class ScanPdf(strelka.Scanner):
    """Collects metadata and extracts files from PDF files."""

    @staticmethod
    def _convert_timestamp(timestamp):
        try:
            return str(datetime.datetime.strptime(timestamp.replace("'", ""), "D:%Y%m%d%H%M%S%z"))
        except:
            return

    def scan(self, data, file, options, expire_at):
        self.event['images'] = 0
        self.event['lines'] = 0
        self.event['links'] = []
        self.event['words'] = 0
        keys = list()

        try:
            with io.BytesIO(data) as pdf_io:
                reader = fitz.open(stream=pdf_io, filetype='pdf')

            # collect metadata
            self.event['author'] = reader.metadata['author']
            self.event['creator'] = reader.metadata['creator']
            self.event['creation_date'] = self._convert_timestamp(reader.metadata['creationDate'])
            self.event['dirty'] = reader.is_dirty
            self.event['embedded_files'] = {
                'count': reader.embfile_count(),
                'names': reader.embfile_names()
            }
            self.event['encrypted'] = reader.is_encrypted
            self.event['needs_pass'] = reader.needs_pass
            self.event['format'] = reader.metadata['format']
            self.event['keywords'] = reader.metadata['keywords']
            self.event['language'] = reader.language
            self.event['modify_date'] = self._convert_timestamp(reader.metadata['modDate'])
            self.event['old_xrefs'] = reader.has_old_style_xrefs
            self.event['pages'] = reader.page_count
            self.event['producer'] = reader.metadata['producer']
            self.event['repaired'] = reader.is_repaired
            self.event['subject'] = reader.metadata['subject']
            self.event['title'] = reader.metadata['title']
            self.event['xrefs'] = reader.xref_length() - 1
            
            #collect phones
            phones = []
            for i in range(self.event["pages"]):
                phones.extend(
                    [
                        re.sub("[^0-9]", "", x)
                        for x in re.findall(
                            phone_numbers,
                            reader.get_page_text(i).replace(
                                "\t", " "
                            ),
                        )
                    ]
                )
            self.event["phones"] = list(set(phones))

            # iterate through xref objects
            for xref in range(1, reader.xref_length()):
                xref_object = reader.xref_object(xref, compressed=True)
                for obj in options.get('objects', []):
                    pattern = f"/{obj}"
                    if pattern in xref_object:
                        keys.append(obj.lower())
                # extract urls from xref
                self.event['links'].extend(re.findall('\"(https?://.*?)\"', xref_object))
            self.event['objects'] = dict(Counter(keys))

            # submit embedded files to strelka
            try:
                for i in range(reader.embfile_count()):
                    props = reader.embfile_info(i)
                    extract_file = strelka.File(
                        name=props['filename'],
                        source=self.name,
                    )
                    for c in strelka.chunk_string(reader.embfile_get(i)):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )
                    self.files.append(extract_file)
            except:
                self.flags.append("embedded_parsing_failure")

            # submit extracted images to strelka
            try:
                for i in range(len(reader)):
                    for img in reader.get_page_images(i):
                        self.event['images'] += 1
                        pix = fitz.Pixmap(reader, img[0])
                        extract_file = strelka.File(
                            name="image",
                            source=self.name,
                        )
                        for c in strelka.chunk_string(pix.tobytes()):
                            self.upload_to_coordinator(
                                extract_file.pointer,
                                c,
                                expire_at,
                            )
                        self.files.append(extract_file)
            except:
                self.flags.append("image_parsing_failure")

            # parse data from each page
            try:
                text = ""
                for page in reader:
                    self.event['lines'] += len(page.get_text().split('\n'))
                    self.event['words'] += len(list(filter(None, page.get_text().split(' '))))
                    # extract links
                    for link in page.get_links():
                        self.event['links'].append(link.get('uri'))

                    text += page.get_text()

                # submit extracted text to strelka
                extract_file = strelka.File(
                    name="text",
                    source=self.name,
                )
                for c in strelka.chunk_string(text):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )
                self.files.append(extract_file)
            except:
                self.flags.append("page_parsing_failure")
        except Exception:
            self.flags.append("pdf_load_error")
