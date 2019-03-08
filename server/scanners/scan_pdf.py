import io
import struct

from pdfminer import converter
from pdfminer import layout
from pdfminer import pdfdocument
from pdfminer import pdfinterp
from pdfminer import pdfpage
from pdfminer import pdfparser
from pdfminer import pdftypes
from pdfminer import psparser

from server import lib


class ScanPdf(lib.StrelkaScanner):
    """Collects metadata and extracts files from PDF files.

    Options:
        extract_text: Boolean that determines if document text should be
            extracted as a child file.
            Defaults to False.
        limit: Maximum number of files to extract.
            Defaults to 2000.
    """
    def scan(self, file_object, options):
        extract_text = options.get('extract_text', False)
        file_limit = options.get('limit', 2000)

        self.metadata['total'] = {'objects': 0, 'extracted': 0}
        extracted_objects = set()

        try:
            with io.BytesIO(file_object.data) as pdf_object:
                parsed_pdf = pdfparser.PDFParser(pdf_object)
                pdf_document = pdfdocument.PDFDocument(parsed_pdf)

                self.metadata.setdefault('annotatedUris', [])
                for xref in pdf_document.xrefs:
                    for object_id in xref.get_objids():
                        self.metadata['total']['objects'] += 1

                        try:
                            object = pdf_document.getobj(object_id)
                            if isinstance(object, dict):
                                for (key, value) in object.items():
                                    if key in ['AA', 'OpenAction']:
                                        file_object.flags.append(f'{self.scanner_name}::auto_action')
                                    if key in ['JS', 'Javascript']:
                                        file_object.flags.append(f'{self.scanner_name}::javascript_embedded')

                                    try:
                                        if key == 'A':
                                            uri = value.get('URI')
                                            if uri is not None and uri not in self.metadata['annotatedUris']:
                                                    self.metadata['annotatedUris'].append(uri)

                                    except AttributeError:
                                        pass

                            if self.metadata['total']['extracted'] >= file_limit:
                                continue
                            if isinstance(object, pdftypes.PDFStream):
                                try:
                                    child_filename = f'{self.scanner_name}::object_{object_id}'
                                    child_fo = lib.StrelkaFile(data=object.get_data(),
                                                               filename=child_filename,
                                                               depth=file_object.depth + 1,
                                                               parent_uid=file_object.uid,
                                                               root_uid=file_object.root_uid,
                                                               parent_hash=file_object.hash,
                                                               root_hash=file_object.root_hash,
                                                               source=self.scanner_name)
                                    if object_id not in extracted_objects:
                                        self.children.append(child_fo)
                                        extracted_objects.add(object_id)
                                        self.metadata['total']['extracted'] += 1

                                except TypeError:
                                    file_object.flags.append(f'{self.scanner_name}::type_error_{object_id}')
                                except struct.error:
                                    file_object.flags.append(f'{self.scanner_name}::struct_error_{object_id}')

                        except ValueError:
                            file_object.flags.append(f'{self.scanner_name}::value_error_{object_id}')
                        except pdftypes.PDFObjectNotFound:
                            file_object.flags.append(f'{self.scanner_name}::object_not_found_{object_id}')
                        except pdftypes.PDFNotImplementedError:
                            file_object.flags.append(f'{self.scanner_name}::not_implemented_error_{object_id}')
                        except pdftypes.PSSyntaxError:
                            file_object.flags.append(f'{self.scanner_name}::ps_syntax_error_{object_id}')

                if extract_text:
                    rsrcmgr = pdfinterp.PDFResourceManager(caching=True)
                    retstr = io.StringIO()
                    la_params = layout.LAParams(detect_vertical=True,
                                                char_margin=1.0,
                                                line_margin=0.3,
                                                word_margin=0.3)
                    device = converter.TextConverter(rsrcmgr, retstr,
                                                     codec='utf-8',
                                                     laparams=la_params)
                    interpreter = pdfinterp.PDFPageInterpreter(rsrcmgr, device)
                    for page in pdfpage.PDFPage.get_pages(pdf_object, set()):
                        try:
                            interpreter.process_page(page)

                        except struct.error:
                            file_object.flags.append(f'{self.scanner_name}::text_struct_error')

                    pdf_object_text = retstr.getvalue()
                    child_filename = f'{self.scanner_name}::text'
                    child_fo = lib.StrelkaFile(data=pdf_object_text,
                                               filename=child_filename,
                                               depth=file_object.depth + 1,
                                               parent_uid=file_object.uid,
                                               root_uid=file_object.root_uid,
                                               parent_hash=file_object.hash,
                                               root_hash=file_object.root_hash,
                                               source=self.scanner_name)
                    self.children.append(child_fo)
                    file_object.flags.append(f'{self.scanner_name}::extracted_text')
                    device.close()
                    retstr.close()

        except IndexError:
            file_object.flags.append(f'{self.scanner_name}::index_error')
        except pdfdocument.PDFEncryptionError:
            file_object.flags.append(f'{self.scanner_name}::encrypted_pdf')
        except pdfparser.PDFSyntaxError:
            file_object.flags.append(f'{self.scanner_name}::pdf_syntax_error')
        except psparser.PSEOF:
            file_object.flags.append(f'{self.scanner_name}::ps_eof')
        except psparser.PSSyntaxError:
            file_object.flags.append(f'{self.scanner_name}::ps_syntax_error')
