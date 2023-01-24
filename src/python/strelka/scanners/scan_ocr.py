import os
import subprocess
import tempfile

from strelka import strelka


class ScanOcr(strelka.Scanner):
    """Collects metadata and extracts optical text from image files.

    Options:
        extract_text: Boolean that determines if optical text should be
            extracted as a child file.
            Defaults to False.
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file, options, expire_at):
        extract_text = options.get('extract_text', False)
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_tess:
                tess_return = subprocess.call(
                    ['tesseract', tmp_data.name, tmp_tess.name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                tess_txt_name = f'{tmp_tess.name}.txt'
                if tess_return == 0:
                    with open(tess_txt_name, 'rb') as tess_txt:
                        ocr_file = tess_txt.read()
                        if ocr_file:
                            self.event['text'] = ocr_file.split()
                            if extract_text:

                                # Send extracted file back to Strelka
                                self.emit_file(ocr_file, name='text')

                else:
                    self.flags.append(f'return_code_{tess_return}')
                os.remove(tess_txt_name)
