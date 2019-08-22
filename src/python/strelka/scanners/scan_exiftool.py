import ast
import json
import subprocess
import tempfile

from strelka import strelka


class ScanExiftool(strelka.Scanner):
    """Collects metadata parsed by Exiftool.

    Options:
        keys: exiftool key values to log in the event.
            Defaults to all.
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file, options, expire_at):
        keys = options.get('keys', [])
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            (stdout, stderr) = subprocess.Popen(
                ['exiftool', '-d', '"%s"', '-j', tmp_data.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).communicate()

            if stdout:
                exiftool_dictionary = json.loads(stdout)[0]

                self.event['keys'] = []
                for k, v in exiftool_dictionary.items():
                    if keys and k not in keys:
                        continue

                    if isinstance(v, str):
                        v = v.strip()
                        v = v.strip('\'"')

                        try:
                            v = ast.literal_eval(v)
                        except (ValueError, SyntaxError):
                            pass

                    self.event['keys'].append({
                        'key': k,
                        'value': v,
                    })
