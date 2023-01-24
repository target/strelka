# Authors: Ryan Borre

import glob
import os
import tlsh
import yaml
from strelka import strelka


class ScanTlsh(strelka.Scanner):
    """Compare file against a list of TLSH values.
    Output from this scanner implies matched file
    has TLSH value lower than defined threshold
    indicating a possible similar file to a known
    file. (e.g., Malware family)

    Attributes:
        tlsh_rules: Dictionary of TLSH hashes and their associated families

    Options:
        location: Location of the TLSH rules file.
            Defaults to '/etc/tlsh'.
        score: TLSH diff score.
            Defaults to 30.
    """

    def init(self):
        self.tlsh_rules = None

    def scan(self, data, file, options, expire_at):
        location = options.get('location', '/etc/strelka/tlsh/')
        score_threshold = options.get('score', 30)

        tlsh_file = tlsh.hash(data)

        if tlsh_file == 'TNULL':
            self.flags.append('null_tlsh')
            return

        try:
            if self.tlsh_rules is None:
                if os.path.isdir(location):
                    self.tlsh_rules = {}
                    for filepath in glob.iglob(f'{location}/**/*.yaml', recursive=True):
                        with open(filepath, 'r') as tlsh_rules:
                            try:
                                self.tlsh_rules.update(yaml.safe_load(tlsh_rules.read()))
                            except yaml.YAMLError:
                                self.flags.append(f"yaml_error: {filepath}")
                                return
                elif os.path.isfile(location):
                    with open(location, 'r') as tlsh_rules:
                        self.tlsh_rules = yaml.safe_load(tlsh_rules.read())
                else:
                    self.flags.append("tlsh_location_not_found")
        except FileNotFoundError:
            self.flags.append("tlsh_files_not_found")

        this_family = None
        this_score = None

        for family, tlsh_hashes in self.tlsh_rules.items():
            for tlsh_hash in tlsh_hashes:
                try:
                    score = tlsh.diff(tlsh_file, tlsh_hash)
                except ValueError:
                    self.flags.append(f"bad_tlsh: {tlsh_hash}")
                    continue
                if score < score_threshold:
                    this_score = score
                    if score <= this_score:
                        this_family = family
                        this_score = score

        self.event['match'] = {'family': this_family, 'score': this_score}
