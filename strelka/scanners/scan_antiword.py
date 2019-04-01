import subprocess
import tempfile

from strelka import core


class ScanAntiword(core.StrelkaScanner):
    """Extracts text from MS Word document files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file_object, options):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_file:
            tmp_file.write(data)
            tmp_file.flush()

            (stdout, stderr) = subprocess.Popen(
                ['antiword', tmp_file.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            ).communicate()

            if stdout:
                file_ = core.StrelkaFile(
                    name='text',
                    source=self.scanner_name,
                )
                self.r0.setex(
                    file_.uid,
                    self.expire,
                    stdout,
                )
                self.files.append(file_)
