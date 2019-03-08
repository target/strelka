import json
import subprocess
import tempfile

from server import lib


class ScanExiftool(lib.StrelkaScanner):
    """Collects metadata parsed by Exiftool.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, file_object, options):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as strelka_file:
            strelka_filename = strelka_file.name
            strelka_file.write(file_object.data)
            strelka_file.flush()

            (stdout, stderr) = subprocess.Popen(['exiftool', '-j', '-n', strelka_filename], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).communicate()
            if stdout:
                exiftool_dictionary = json.loads(stdout)[0]
                self.metadata.setdefault('exiftool', [])
                for (key, value) in exiftool_dictionary.items():
                    if isinstance(value, str):
                        value = value.strip()
                    exiftool_entry = {'field': key, 'value': value}
                    if exiftool_entry not in self.metadata['exiftool']:
                        self.metadata['exiftool'].append(exiftool_entry)
