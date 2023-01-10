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
        location_rules = options.get('location_rules', '/etc/capa/rules/')
        location_signatures = options.get('location_signatures', '/etc/capa/signatures/')
        scanner_timeout = options.get('scanner_timeout', 20)

        # Check rules and signatures locationss
        if os.path.isdir(location_rules):
            if not os.listdir(location_rules):
                self.flags.append('error_norules')
                return
        else:
            self.flags.append('error_norules')
            return

        if os.path.isdir(location_signatures):
            if not os.listdir(location_signatures):
                self.flags.append('error_nosignatures')
                return
        else:
            self.flags.append('error_nosignatures')
            return

        try:
            with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
                tmp_data.write(data)
                tmp_data.flush()

                try:
                    (stdout, stderr) = subprocess.Popen(
                            ['capa', '-j', '-r', location_rules, '-s', location_signatures, tmp_data.name],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        ).communicate(timeout=scanner_timeout)
                except subprocess.TimeoutExpired:
                    self.flags.append('process_timed_out')
                    return
                except Exception as e:
                    self.flags.append('error_processing')
                    return

                if stdout:
                    try:
                        capa_json = json.loads(stdout.rstrip())
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
        except Exception as e:
            self.flags.append('error_execution')
