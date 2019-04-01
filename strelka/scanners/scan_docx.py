import io

import docx

from strelka import core


class ScanDocx(core.StrelkaScanner):
    """Collects metadata and extracts text from docx files.

    Options:
        extract_text: Boolean that determines if document text should be
            extracted as a child file.
            Defaults to False.
    """
    def scan(self, data, file_object, options):
        extract_text = options.get('extract_text', False)

        with io.BytesIO(data) as docx_object:
            docx_doc = docx.Document(docx_object)
            self.metadata['author'] = docx_doc.core_properties.author
            self.metadata['category'] = docx_doc.core_properties.category
            self.metadata['comments'] = docx_doc.core_properties.comments
            self.metadata['contentStatus'] = docx_doc.core_properties.content_status
            if docx_doc.core_properties.created is not None:
                self.metadata['created'] = docx_doc.core_properties.created.isoformat(timespec='seconds')
            self.metadata['identifier'] = docx_doc.core_properties.identifier
            self.metadata['keywords'] = docx_doc.core_properties.keywords
            self.metadata['language'] = docx_doc.core_properties.language
            self.metadata['lastModifiedBy'] = docx_doc.core_properties.last_modified_by
            if docx_doc.core_properties.last_printed is not None:
                self.metadata['lastPrinted'] = docx_doc.core_properties.last_printed.isoformat(timespec='seconds')
            if docx_doc.core_properties.modified is not None:
                self.metadata['modified'] = docx_doc.core_properties.modified.isoformat(timespec='seconds')
            self.metadata['revision'] = docx_doc.core_properties.revision
            self.metadata['subject'] = docx_doc.core_properties.subject
            self.metadata['title'] = docx_doc.core_properties.title
            self.metadata['version'] = docx_doc.core_properties.version

            if extract_text:
                file_ = core.StrelkaFile(
                    name='text',
                    source=self.scanner_name,
                )
                for paragraph in docx_doc.paragraphs:
                    self.r0.append(file_.uid, paragraph.text)
                    self.r0.expire(file_.uid, self.expire)
                self.files.append(file_)
