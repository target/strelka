import os
import subprocess
import tempfile

from strelka import core
from strelka.scanners import util


class ScanOcr(core.StrelkaScanner):
    """Collects metadata and extracts optical text from image files.

    Options:
        extract_text: Boolean that determines if optical text should be
            extracted as a child file.
            Defaults to False.
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, st_file, options):
        extract_text = options.get('extract_text', False)
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as st_tmp:
            st_tmp.write(self.data)
            st_tmp.flush()

            with tempfile.NamedTemporaryFile(dir=tmp_directory) as tess_tmp:
                tess_return = subprocess.call(
                    ['tesseract', st_tmp.name, tess_tmp.name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                tess_txt_name = f'{tess_tmp.name}.txt'
                if tess_return == 0:
                    with open(tess_txt_name, 'rb') as tess_txt:
                        ocr_file = tess_txt.read()
                        if ocr_file:
                            self.metadata['text'] = ocr_file.split()
                            if extract_text:
                                ex_file = core.StrelkaFile(
                                    name='text',
                                    source=self.name,
                                )
                                for c in util.chunk_string(ocr_file):
                                    p = self.fk.pipeline()
                                    p.rpush(ex_file.uid, c)
                                    p.expire(ex_file.uid, self.expire)
                                    p.execute()
                                self.files.append(ex_file)

                else:
                    self.flags.add('return_code_{tess_return}')
                os.remove(tess_txt_name)
