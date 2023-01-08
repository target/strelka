import re
import os
import json
import subprocess
import tempfile

from strelka import strelka


class ScanCapa(strelka.Scanner):
    """Executes FireEye CAPA with versioned rules and provides known capabilities and MITRE ATT&CK matches.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
        location: Location of the CAPA rules file or directory.
            Defaults to '/etc/capa/'
    """

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get('tmp_directory', '/tmp/')
        location = options.get('location', '/etc/capa/')

        # Only run if rules file exists, otherwise return no rules error
        if len(os.listdir(location)) != 0:
            try:
                with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
                    tmp_data.write(data)
                    tmp_data.flush()

                    try:
                        (stdout, stderr) = subprocess.Popen(
                            ['/tmp/capa', tmp_data.name, '-r', location, '-j'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL
                        ).communicate()
                    except:
                        self.flags.append('error_processing')
                        return

                    if stdout:
                        # Observed extraneous data in stdout requiring string trimming. Parse out JSON response.
                        # This can be fixed when CAPA is aviailable as a Python 3 library.
                        try:
                            stdout = stdout[stdout.find(b'{'):]
                            stdout = stdout[:stdout.rfind(b'}')]
                            stdout += b'}'
                            capa_json = json.loads(stdout)
                        except:
                            self.flags.append('error_parsing')
                            return

                        try:
                            # Sets are used to remove duplicative values
                            self.event['matches'] = set()
                            self.event['mitre_techniques'] = set()
                            self.event['mitre_ids'] = set()

                            for k, v in capa_json['rules'].items():
                                self.event['matches'].add(k)
                                if 'att&ck' in v['meta']:
                                    result = re.search(r'^([^:]+)::([^\[)]+)\s\[([^\]]+)\]', v['meta']['att&ck'][0])
                                    self.event['mitre_techniques'].add(result.group(2))
                                    self.event['mitre_ids'].add(result.group(3))
                            # For consistency, convert sets to list
                            self.event['matches'] = list(self.event['matches'])
                            self.event['mitre_techniques'] = list(self.event['mitre_techniques'])
                            self.event['mitre_ids'] = list(self.event['mitre_ids'])
                        except:
                            self.flags.append('error_collection')
            except:
                self.flags.append('error_execution')
        else:
            self.flags.append('error_norules')


