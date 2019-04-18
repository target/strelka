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

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as st_tmp:
            st_tmp.write(data)
            st_tmp.flush()

            (stdout, stderr) = subprocess.Popen(
                ['exiftool', '-j', '-n', st_tmp.name],
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
