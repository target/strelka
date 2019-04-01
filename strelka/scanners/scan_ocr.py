import os
import subprocess
import tempfile

from strelka import core


class ScanOcr(core.StrelkaScanner):
    """Collects metadata and extracts optical text from image files.

    Options:
        extract_text: Boolean that determines if optical text should be
            extracted as a child file.
            Defaults to False.
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file_object, options):
        extract_text = options.get('extract_text', False)
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp:
            tmp.write(data)
            tmp.flush()

            with tempfile.NamedTemporaryFile(dir=tmp_directory) as tess:
                tess_return = subprocess.call(
                    ['tesseract', tmp.name, tess.name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                tess_txt_name = f'{tess.name}.txt'
                if tess_return == 0:
                    with open(tess_txt_name, 'rb') as tess_txt:
                        ocr_file = tess_txt.read()
                        if ocr_file:
                            self.metadata['text'] = ocr_file.split()
                            if extract_text:
                                file_ = core.StrelkaFile(
                                    name='text',
                                    source=self.scanner_name,
                                )
                                self.r0.setex(
                                    file_.uid,
                                    self.expire,
                                    ocr_file,
                                )
                                self.files.append(file_)

                else:
                    self.flags.add(f'{self.scanner_name}::return_code_{tess_return}')
                os.remove(tess_txt_name)
