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

from strelka import core


class ScanPdf(core.StrelkaScanner):
    """Collects metadata and extracts files from PDF files.

    Options:
        extract_text: Boolean that determines if document text should be
            extracted as a child file.
            Defaults to False.
        limit: Maximum number of files to extract.
            Defaults to 2000.
    """
    def scan(self, data, file_object, options):
        extract_text = options.get('extract_text', False)
        file_limit = options.get('limit', 2000)

        self.metadata['total'] = {'objects': 0, 'extracted': 0}
        extracted_objects = set()

        try:
            with io.BytesIO(data) as data:
                parsed = pdfparser.PDFParser(data)
                pdf = pdfdocument.PDFDocument(parsed)

                self.metadata.setdefault('annotatedUris', [])
                for xref in pdf.xrefs:
                    for object_id in xref.get_objids():
                        self.metadata['total']['objects'] += 1

                        try:
                            object = pdf.getobj(object_id)
                            if isinstance(object, dict):
                                for (key, value) in object.items():
                                    if key in ['AA', 'OpenAction']:
                                        self.flags.add(f'{self.scanner_name}::auto_action')
                                    if key in ['JS', 'Javascript']:
                                        self.flags.add(f'{self.scanner_name}::javascript_embedded')

                                    try:
                                        if key == 'A':
                                            uri = value.get('URI')
                                            if uri not in self.metadata['annotatedUris']:
                                                self.metadata['annotatedUris'].append(uri)

                                    except AttributeError:
                                        pass

                            if self.metadata['total']['extracted'] >= file_limit:
                                continue
                            if isinstance(object, pdftypes.PDFStream):
                                try:
                                    if object_id not in extracted_objects:
                                        file_ = core.StrelkaFile(
                                            name=f'object_{object_id}',
                                            source=self.scanner_name,
                                        )
                                        self.r0.setex(
                                            file_.uid,
                                            self.expire,
                                            object.get_data(),
                                        )
                                        self.files.append(file_)
                                        extracted_objects.add(object_id)
                                        self.metadata['total']['extracted'] += 1

                                except TypeError:
                                    self.flags.add(f'{self.scanner_name}::type_error_{object_id}')
                                except struct.error:
                                    self.flags.add(f'{self.scanner_name}::struct_error_{object_id}')

                        except ValueError:
                            self.flags.add(f'{self.scanner_name}::value_error_{object_id}')
                        except pdftypes.PDFObjectNotFound:
                            self.flags.add(f'{self.scanner_name}::object_not_found_{object_id}')
                        except pdftypes.PDFNotImplementedError:
                            self.flags.add(f'{self.scanner_name}::not_implemented_error_{object_id}')
                        except psparser.PSSyntaxError:
                            self.flags.add(f'{self.scanner_name}::ps_syntax_error_{object_id}')

                if extract_text:
                    rsrcmgr = pdfinterp.PDFResourceManager(caching=True)
                    retstr = io.StringIO()
                    la_params = layout.LAParams(
                        detect_vertical=True,
                        char_margin=1.0,
                        line_margin=0.3,
                        word_margin=0.3,
                    )
                    device = converter.TextConverter(
                        rsrcmgr,
                        retstr,
                        codec='utf-8',
                        laparams=la_params,
                    )
                    interpreter = pdfinterp.PDFPageInterpreter(rsrcmgr, device)
                    for page in pdfpage.PDFPage.get_pages(data, set()):
                        try:
                            interpreter.process_page(page)

                        except struct.error:
                            self.flags.add(f'{self.scanner_name}::text_struct_error')

                    file_ = core.StrelkaFile(
                        name='text',
                        source=self.scanner_name,
                    )
                    self.r0.setex(
                        file_.uid,
                        self.expire,
                        retstr.getvalue(),
                    )
                    self.files.append(file_)
                    self.flags.add(f'{self.scanner_name}::extracted_text')
                    device.close()
                    retstr.close()

        except IndexError:
            self.flags.add(f'{self.scanner_name}::index_error')
        except pdfdocument.PDFEncryptionError:
            self.flags.add(f'{self.scanner_name}::encrypted_pdf')
        except pdfparser.PDFSyntaxError:
            self.flags.add(f'{self.scanner_name}::pdf_syntax_error')
        except psparser.PSEOF:
            self.flags.add(f'{self.scanner_name}::ps_eof')
        except psparser.PSSyntaxError:
            self.flags.add(f'{self.scanner_name}::ps_syntax_error')
