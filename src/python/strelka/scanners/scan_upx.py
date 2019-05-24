import os
import subprocess
import tempfile

from strelka import strelka


class ScanUpx(strelka.Scanner):
    """Decompresses UPX packed files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            upx_return = subprocess.call(
                ['upx', '-d', tmp_data.name, '-o', f'{tmp_data.name}_upx'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if upx_return == 0:
                with open(f'{tmp_data.name}_upx', 'rb') as upx_fin:
                    upx_file = upx_fin.read()
                    upx_size = len(upx_file)
                    if upx_size > file.size:
                        extract_file = strelka.File(
                            source=self.name,
                        )
                        for c in strelka.chunk_string(upx_file):
                            self.upload_to_coordinator(
                                extract_file.pointer,
                                c,
                                expire_at,
                            )
                        self.files.append(extract_file)

                os.remove(f'{tmp_data.name}_upx')

            else:
                self.flags.append('return_code_{upx_return}')
