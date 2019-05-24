import io

import docx

from strelka import strelka


class ScanDocx(strelka.Scanner):
    """Collects metadata and extracts text from docx files.

    Options:
        extract_text: Boolean that determines if document text should be
            extracted as a child file.
            Defaults to False.
    """
    def scan(self, data, file, options, expire_at):
        extract_text = options.get('extract_text', False)

        with io.BytesIO(data) as docx_io:
            docx_doc = docx.Document(docx_io)
            self.event['author'] = docx_doc.core_properties.author
            self.event['category'] = docx_doc.core_properties.category
            self.event['comments'] = docx_doc.core_properties.comments
            self.event['content_status'] = docx_doc.core_properties.content_status
            if docx_doc.core_properties.created is not None:
                self.event['created'] = docx_doc.core_properties.created.isoformat()
            self.event['identifier'] = docx_doc.core_properties.identifier
            self.event['keywords'] = docx_doc.core_properties.keywords
            self.event['language'] = docx_doc.core_properties.language
            self.event['last_modified_by'] = docx_doc.core_properties.last_modified_by
            if docx_doc.core_properties.last_printed is not None:
                self.event['last_printed'] = docx_doc.core_properties.last_printed.isoformat()
            if docx_doc.core_properties.modified is not None:
                self.event['modified'] = docx_doc.core_properties.modified.isoformat()
            self.event['revision'] = docx_doc.core_properties.revision
            self.event['subject'] = docx_doc.core_properties.subject
            self.event['title'] = docx_doc.core_properties.title
            self.event['version'] = docx_doc.core_properties.version

            if extract_text:
                extract_file = strelka.File(
                    name='text',
                    source=self.name,
                )

                for paragraph in docx_doc.paragraphs:
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        paragraph.text,
                        expire_at,
                    )

                self.files.append(extract_file)
