import json

from strelka import core


class ScanJson(core.StrelkaScanner):
    """Collects keys from JSON files."""
    def scan(self, st_file, options):
        self.metadata.setdefault('keys', [])

        try:
            self._get_keys(self, json.loads(self.data.decode()))

        except UnicodeDecodeError:
            self.flags.add('unicode_decode_error')
        except json.decoder.JSONDecodeError:
            self.flags.add('json_decode_error')

    @staticmethod
    def _get_keys(self, variable):
        """Recursively parses JSON.

        Args:
            variable: Variable to recursively parse.
        """
        if isinstance(variable, dict):
            for (key, value) in variable.items():
                if key not in self.metadata['keys']:
                    self.metadata['keys'].append(key)
                self._get_keys(self, value)
        elif isinstance(variable, list):
            for v in variable:
                self._get_keys(self, v)
