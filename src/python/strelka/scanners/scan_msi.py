import json
import subprocess
import tempfile

from strelka import strelka


class ScanMsi(strelka.Scanner):
    """Collects metadata parsed by Exiftool.

    Options:
        keys: exiftool key values to log in the event.
            Defaults to all.
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """

    def scan(self, data, file, options, expire_at):
        # Get a list of keys to collect from the MSI file
        keys = options.get("keys", [])

        # Get the temporary directory to write the MSI file to
        tmp_directory = options.get("tmp_directory", "/tmp/")

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            # Write the MSI data to the temporary file
            tmp_data.write(data)
            tmp_data.flush()

            # Run exiftool to extract metadata from the file
            try:
                (stdout, stderr) = subprocess.Popen(
                    ["exiftool", "-d", '"%s"', "-j", tmp_data.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                ).communicate()
            except strelka.ScannerTimeout:
                raise
            except Exception as e:
                # Handle any exceptions raised while running exiftool
                self.flags.append(f"msi_extract_error: {e}")
                return

            if stdout:
                # Load the metadata from exiftool's JSON output
                try:
                    exiftool_dictionary = json.loads(stdout)[0]
                except ValueError as e:
                    # Handle any errors while parsing the JSON output
                    self.flags.append(f"msi_parse_error: {e}")
                    return

                for k, v in exiftool_dictionary.items():
                    # Only collect the keys specified in the `keys` list
                    if keys and k not in keys:
                        continue

                    # Add the metadata key and value to the event
                    self.event[k] = v
