# Authors: Ryan Borre, Paul Hutelmyer

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
        # Get the location of the TLSH rule files and the score threshold
        location = options.get("location", "/etc/strelka/tlsh/")
        score_threshold = options.get("score", 30)

        # Hash the data
        tlsh_file = tlsh.hash(data)

        # If the hash is "TNULL", add a flag and return
        if tlsh_file == "TNULL":
            return

        try:
            # If the TLSH rules have not been loaded yet, load them from the specified location
            if self.tlsh_rules is None:
                if os.path.isdir(location):
                    self.tlsh_rules = {}
                    # Load all YAML files in the directory recursively
                    for filepath in glob.iglob(f"{location}/**/*.yaml", recursive=True):
                        with open(filepath, "r") as tlsh_rules:
                            try:
                                self.tlsh_rules.update(
                                    yaml.safe_load(tlsh_rules.read())
                                )
                            except yaml.YAMLError:
                                self.flags.append(f"yaml_error: {filepath}")
                                return
                elif os.path.isfile(location):
                    with open(location, "r") as tlsh_rules:
                        self.tlsh_rules = yaml.safe_load(tlsh_rules.read())
                else:
                    self.flags.append("tlsh_location_not_found")
        except FileNotFoundError:
            self.flags.append("tlsh_files_not_found")

        # Initialize variables to store the family, score, and matched TLSH hash
        this_family = None
        this_score = score_threshold
        matched_tlsh_hash = None

        # Iterate over the TLSH rule hashes
        for family, tlsh_hashes in self.tlsh_rules.items():
            for tlsh_hash in tlsh_hashes:
                try:
                    # Calculate the difference score between the file hash and the rule hash
                    score = tlsh.diffxlen(tlsh_file, tlsh_hash)
                except ValueError:
                    self.flags.append(f"bad_tlsh: {tlsh_hash}")
                    continue
                if score < score_threshold:
                    # If the score is less than the threshold, update matches
                    if score <= this_score:
                        this_family = family
                        this_score = score
                        matched_tlsh_hash = tlsh_hash

        if this_family:
            self.event["match"] = {
                "family": this_family,
                "score": this_score,
                "tlsh": matched_tlsh_hash,
            }
