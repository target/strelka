import io

import docx

from server import objects


class ScanDocx(objects.StrelkaScanner):
    """Collects metadata and extracts text from docx files.

    Options:
        extract_text: Boolean that determines if document text should be
            extracted as a child file.
            Defaults to False.
    """
    def scan(self, file_object, options):
        extract_text = options.get("extract_text", False)

        with io.BytesIO(file_object.data) as docx_object:
            docx_file = docx.Document(docx_object)
            core_properties = docx_file.core_properties
            if core_properties.author is not None:
                self.metadata["author"] = core_properties.author
            if core_properties.category is not None:
                self.metadata["category"] = core_properties.category
            if core_properties.comments is not None:
                self.metadata["comments"] = core_properties.comments
            if core_properties.content_status is not None:
                self.metadata["contentStatus"] = core_properties.content_status
            if core_properties.created is not None:
                self.metadata["created"] = core_properties.created.isoformat(timespec="seconds")
            if core_properties.identifier is not None:
                self.metadata["identifier"] = core_properties.identifier
            if core_properties.keywords is not None:
                self.metadata["keywords"] = core_properties.keywords
            if core_properties.language is not None:
                self.metadata["language"] = core_properties.language
            if core_properties.last_modified_by is not None:
                self.metadata["lastModifiedBy"] = core_properties.last_modified_by
            if core_properties.last_printed is not None:
                self.metadata["lastPrinted"] = core_properties.last_printed.isoformat(timespec="seconds")
            if core_properties.modified is not None:
                self.metadata["modified"] = core_properties.modified.isoformat(timespec="seconds")
            if core_properties.revision is not None:
                self.metadata["revision"] = core_properties.revision
            if core_properties.subject is not None:
                self.metadata["subject"] = core_properties.subject
            if core_properties.title is not None:
                self.metadata["title"] = core_properties.title
            if core_properties.version is not None:
                self.metadata["version"] = core_properties.version

            if extract_text:
                docx_text = []
                for paragraph in docx_file.paragraphs:
                    docx_text.append(paragraph.text)
                child_filename = f"{self.scanner_name}::text"
                child_fo = objects.StrelkaFile(data="".join(docx_text),
                                               filename=child_filename,
                                               depth=file_object.depth + 1,
                                               parent_uid=file_object.uid,
                                               root_uid=file_object.root_uid,
                                               parent_hash=file_object.hash,
                                               root_hash=file_object.root_hash,
                                               source=self.scanner_name)
                self.children.append(child_fo)
