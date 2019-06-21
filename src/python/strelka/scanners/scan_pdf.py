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
    def scan(self, data, file, options, expire_at):
        extract_text = options.get('extract_text', False)
        file_limit = options.get('limit', 2000)

        self.event['total'] = {'objects': 0, 'extracted': 0}
        extracted_objects = set()

        try:
            with io.BytesIO(data) as pdf_io:
                parsed = pdfparser.PDFParser(pdf_io)
                pdf = pdfdocument.PDFDocument(parsed)

                self.event.setdefault('annotated_uris', [])
                for xref in pdf.xrefs:
                    for object_id in xref.get_objids():
                        self.event['total']['objects'] += 1

                        try:
                            pdf_object = pdf.getobj(object_id)
                            if isinstance(pdf_object, dict):
                                for (key, value) in pdf_object.items():
                                    if key in ['AA', 'OpenAction']:
                                        self.flags.append('auto_action')
                                    if key in ['JS', 'Javascript']:
                                        self.flags.append('javascript_embedded')

                                    try:
                                        if key == 'A':
                                            uri = value.get('URI')
                                            if uri not in self.event['annotated_uris']:
                                                self.event['annotated_uris'].append(uri)

                                    except AttributeError:
                                        pass

                            if self.event['total']['extracted'] >= file_limit:
                                continue
                            if isinstance(pdf_object, pdftypes.PDFStream):
                                try:
                                    if object_id not in extracted_objects:
                                        extract_file = strelka.File(
                                            name=f'object_{object_id}',
                                            source=self.name,
                                        )

                                        for c in strelka.chunk_string(pdf_object.get_data()):
                                            self.upload_to_coordinator(
                                                extract_file.pointer,
                                                c,
                                                expire_at,
                                            )

                                        self.files.append(extract_file)
                                        self.event['total']['extracted'] += 1
                                        extracted_objects.add(object_id)

                                except TypeError:
                                    self.flags.append('type_error_{object_id}')
                                except struct.error:
                                    self.flags.append('struct_error_{object_id}')

                        except ValueError:
                            self.flags.append('value_error_{object_id}')
                        except pdftypes.PDFObjectNotFound:
                            self.flags.append('object_not_found_{object_id}')
                        except pdftypes.PDFNotImplementedError:
                            self.flags.append('not_implemented_error_{object_id}')
                        except psparser.PSSyntaxError:
                            self.flags.append('ps_syntax_error_{object_id}')

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
                            self.flags.append('text_struct_error')

                    extract_file = strelka.File(
                        name='text',
                        source=self.name,
                    )
                    for c in strelka.chunk_string(retstr.getvalue()):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )
                    self.files.append(extract_file)

                    self.flags.append('extracted_text')
                    device.close()
                    retstr.close()

        except IndexError:
            self.flags.append('index_error')
        except pdfdocument.PDFEncryptionError:
            self.flags.append('encrypted_pdf')
        except pdfparser.PDFSyntaxError:
            self.flags.append('pdf_syntax_error')
        except psparser.PSEOF:
            self.flags.append('ps_eof')
        except psparser.PSSyntaxError:
            self.flags.append('ps_syntax_error')
