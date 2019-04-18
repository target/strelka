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

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as st_tmp:
            st_tmp.write(data)
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
                                extract_file = strelka.File(
                                    name='text',
                                    source=self.name,
                                )

                                for c in strelka.chunk_string(ocr_file):
                                    self.upload_to_cache(
                                        extract_file.pointer,
                                        c,
                                        expire_at,
                                    )

                                self.files.append(extract_file)

                else:
                    self.flags.append('return_code_{tess_return}')
                os.remove(tess_txt_name)
