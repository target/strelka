import entropy

from strelka import core


class ScanEntropy(core.StrelkaScanner):
    """Calculates entropy of files."""
    def scan(self, st_file, options):
        self.metadata['entropy'] = entropy.shannon_entropy(self.data)
