import subprocess
import tempfile

from strelka import core
from strelka.scanners import util


class ScanAntiword(core.StrelkaScanner):
    """Extracts text from MS Word document files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, st_file, options):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as st_tmp:
            st_tmp.write(self.data)
            st_tmp.flush()

            (stdout, stderr) = subprocess.Popen(
                ['antiword', st_tmp.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            ).communicate()

            if stdout:
                ex_file = core.StrelkaFile(
                    name='text',
                    source=self.name,
                )
                for c in util.chunk_string(stdout):
                    p = self.fk.pipeline()
                    p.rpush(ex_file.uid, c)
                    p.expire(ex_file.uid, self.expire)
                    p.execute()
                self.files.append(ex_file)
