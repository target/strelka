import json
import subprocess
import tempfile

from strelka import strelka


class ScanExiftool(strelka.Scanner):
    """Collects metadata parsed by Exiftool.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            (stdout, stderr) = subprocess.Popen(
                ['exiftool', '-j', '-n', tmp_data.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).communicate()

            if stdout:
                exiftool_dictionary = json.loads(stdout)[0]
                self.event.setdefault('exiftool', [])
                for (key, value) in exiftool_dictionary.items():
                    if isinstance(value, str):
                        value = value.strip()
                    exiftool_entry = {'field': key, 'value': value}
                    if exiftool_entry not in self.event['exiftool']:
                        self.event['exiftool'].append(exiftool_entry)
