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
                            ['capa', '-j', '-r', location, '-s', location, tmp_data.name],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL
                        ).communicate()
                    except:
                        self.flags.append('error_processing')
                        return

                    if stdout:
                        try:
                            capa_json = json.loads(stdout.rstrip())
                            print(json.dumps(capa_json))
                        except:
                            self.flags.append('error_parsing')
                            return

                        try:
                            # Sets are used to remove duplicative values
                            self.event['matches'] = []
                            self.event['mitre_techniques'] = []
                            self.event['mitre_ids'] = []

                            for rule_key, rule_value in capa_json['rules'].items():
                                self.event['matches'].append(rule_key)
                                if 'attack' in rule_value.get('meta', []):
                                    if attacks := rule_value.get('meta', []).get('attack', []):
                                        for attack in attacks:
                                            self.event['mitre_techniques'].append(
                                                "::".join(attack.get("parts", [])))
                                            self.event['mitre_ids'].append(attack.get("id", ""))
                            # For consistency, convert sets to list
                            self.event['matches'] = list(set(self.event['matches']))
                            self.event['mitre_techniques'] = list(set(self.event['mitre_techniques']))
                            self.event['mitre_ids'] = list(set(self.event['mitre_ids']))
                        except:
                            self.flags.append('error_collection')
            except:
                self.flags.append('error_execution')
        else:
            self.flags.append('error_norules')


