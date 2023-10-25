import json
import subprocess
import tempfile

from strelka import strelka


class ScanExiftool(strelka.Scanner):
    """Collects metadata parsed by Exiftool.

    This scanner uses Exiftool to extract metadata from files and logs the
    extracted key-value pairs.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get("tmp_directory", "/tmp/")

        # Use a temporary file to store the data for processing with Exiftool
        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            try:
                # Execute exiftool and retrieve JSON metadata output
                (stdout, stderr) = subprocess.Popen(
                    ["exiftool", "-j", tmp_data.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                ).communicate()

                if stdout:
                    # Load metadata from stdout and update the event dictionary with it
                    # Converts fields with spaces to underscores to accommodate
                    # searchability (i.e.,  "File Name" to "file_name")
                    metadata = json.loads(stdout)[0]
                    for key, value in metadata.items():
                        formatted_key = key.replace(" ", "_").replace("/", "_").lower()

                        # Convert any lists to a comma-separated string
                        if isinstance(value, list):
                            value = ", ".join(map(str, value))

                        self.event[formatted_key] = value

            # Handle potential errors from exiftool and JSON decoding
            except subprocess.CalledProcessError as e:
                self.flags.append(f"exiftool_error: Subprocess Error - {str(e)}")
            except json.JSONDecodeError as e:
                self.flags.append(f"exiftool_error: JSON Decode Error - {str(e)}")
            except Exception as e:
                self.flags.append(f"exiftool_error: General Error - {str(e)}")
