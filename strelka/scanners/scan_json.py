import json

from strelka import core


class ScanJson(core.StrelkaScanner):
    """Collects keys from JSON files."""
    def scan(self, data, file_object, options):
        self.metadata.setdefault('keys', [])

        try:
            self._get_keys(self, json.loads(data.decode()))

        except UnicodeDecodeError:
            self.flags.add(f'{self.scanner_name}::unicode_decode_error')
        except json.decoder.JSONDecodeError:
            self.flags.add(f'{self.scanner_name}::json_decode_error')

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
