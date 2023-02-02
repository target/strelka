import json

from strelka import strelka


class ScanJson(strelka.Scanner):
    """Collects keys from JSON files."""

    def scan(self, data, file, options, expire_at):
        self.event.setdefault("keys", [])

        try:
            self._get_keys(self, json.loads(data.decode()))

        except UnicodeDecodeError:
            self.flags.append("unicode_decode_error")
        except json.decoder.JSONDecodeError:
            self.flags.append("json_decode_error")

    @staticmethod
    def _get_keys(self, variable):
        """Recursively parses JSON.

        Args:
            variable: Variable to recursively parse.
        """
        if isinstance(variable, dict):
            for key, value in variable.items():
                if key not in self.event["keys"]:
                    self.event["keys"].append(key)
                self._get_keys(self, value)
        elif isinstance(variable, list):
            for v in variable:
                self._get_keys(self, v)
