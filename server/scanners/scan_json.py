import json

from server import lib


class ScanJson(lib.StrelkaScanner):
    """Collects keys from JSON files."""
    def scan(self, file_object, options):
        self.metadata.setdefault('keys', [])

        try:
            self._get_keys(self, json.loads(file_object.data.decode()))

        except UnicodeDecodeError:
            file_object.flags.append(f'{self.scanner_name}::unicode_decode_error')
        except json.decoder.JSONDecodeError:
            file_object.flags.append(f'{self.scanner_name}::json_decode_error')

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
