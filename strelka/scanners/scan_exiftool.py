import json
import subprocess
import tempfile

from strelka import core


class ScanExiftool(core.StrelkaScanner):
    """Collects metadata parsed by Exiftool.

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
                ['exiftool', '-j', '-n', tmp_file.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).communicate()

            if stdout:
                exiftool_dictionary = json.loads(stdout)[0]
                self.metadata.setdefault('exiftool', [])
                for (key, value) in exiftool_dictionary.items():
                    if isinstance(value, str):
                        value = value.strip()
                    exiftool_entry = {'field': key, 'value': value}
                    if exiftool_entry not in self.metadata['exiftool']:
                        self.metadata['exiftool'].append(exiftool_entry)
