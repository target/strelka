import entropy

from strelka import core


class ScanEntropy(core.StrelkaScanner):
    """Calculates entropy of files."""
    def scan(self, data, file_object, options):
        self.metadata['entropy'] = entropy.shannon_entropy(data)
