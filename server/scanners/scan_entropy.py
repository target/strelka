import entropy

from server import lib


class ScanEntropy(lib.StrelkaScanner):
    """Calculates entropy of files."""
    def scan(self, file_object, options):
        self.metadata['entropy'] = entropy.shannon_entropy(file_object.data)
