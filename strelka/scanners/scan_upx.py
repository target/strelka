import os
import subprocess
import tempfile

from strelka import core


class ScanUpx(core.StrelkaScanner):
    """Decompresses UPX packed files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file_object, options):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp:
            tmp.write(data)
            tmp.flush()

            upx_return = subprocess.call(
                ['upx', '-d', tmp.name, '-o', f'{tmp.name}_upx'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if upx_return == 0:
                with open(f'{tmp.name}_upx', 'rb') as upx_fin:
                    upx_file = upx_fin.read()
                    upx_size = len(upx_file)
                    if upx_size > file_object.size:
                        file_ = core.StrelkaFile(
                            source=self.scanner_name,
                        )
                        self.r0.setex(
                            file_.uid,
                            self.expire,
                            upx_file,
                        )
                        self.files.append(file_)
                os.remove(f'{tmp.name}_upx')

            else:
                self.flags.add(f'{self.scanner_name}::return_code_{upx_return}')
