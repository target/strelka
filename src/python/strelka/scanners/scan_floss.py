import json
import subprocess
import tempfile

from strelka import strelka


class ScanFloss(strelka.Scanner):
    """Executes FireEye FLOSS.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
        limit: Maximum amount of strings to collect.
            Defaults to 100.
    """

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get('tmp_directory', '/tmp/')
        limit = options.get('limit', 100)

        self.event['decoded'] = []
        self.event['stack'] = []

        try:
            with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
                # Write out the sample to a temporary file
                tmp_data.write(data)

                try:
                    # Write out floss results to a temporary file for processing
                    with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_output:
                        try:
                            subprocess.Popen(
                                ['/tmp/floss', '-q', '--no-static-strings', '-o', tmp_output.name, tmp_data.name],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL
                            ).communicate()
                            floss_json = json.load(tmp_output)
                        except strelka.ScannerTimeout:
                            raise
                        except Exception:
                            self.flags.append('error_processing')
                            return

                        try:
                            if floss_json['strings']['decoded_strings']:
                                self.event['decoded'] = floss_json['strings']['decoded_strings'][:limit]
                            if floss_json['strings']['stack_strings']:
                                self.event['stack'] = floss_json['strings']['stack_strings'][:limit]
                        except strelka.ScannerTimeout:
                            raise
                        except Exception:
                            self.flags.append('error_parsing')
                            return
                except strelka.ScannerTimeout:
                    raise
                except Exception:
                    self.flags.append('error_execution')
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append('error_execution')


