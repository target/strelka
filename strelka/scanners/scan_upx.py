import os
import subprocess
import tempfile

from strelka import core
from strelka.scanners import util


class ScanUpx(core.StrelkaScanner):
    """Decompresses UPX packed files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, st_file, options):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as st_tmp:
            st_tmp.write(self.data)
            st_tmp.flush()

            upx_return = subprocess.call(
                ['upx', '-d', st_tmp.name, '-o', f'{st_tmp.name}_upx'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if upx_return == 0:
                with open(f'{st_tmp.name}_upx', 'rb') as upx_fin:
                    upx_file = upx_fin.read()
                    upx_size = len(upx_file)
                    if upx_size > st_file.size:
                        ex_file = core.StrelkaFile(
                            source=self.name,
                        )
                        for c in util.chunk_string(upx_file):
                            p = self.fk.pipeline()
                            p.rpush(ex_file.uid, c)
                            p.expire(ex_file.uid, self.expire)
                            p.execute()
                        self.files.append(ex_file)

                os.remove(f'{st_tmp.name}_upx')

            else:
                self.flags.add('return_code_{upx_return}')
