import shutil
import subprocess
import tempfile

from strelka import strelka


class ScanClamav(strelka.Scanner):
    """
    This scanner runs against a given file and returns a ClamAV scan that has a determination if the file is infected
    or not based on the ClamAV signature database.

    Scanner Type: Collection

    Attributes:
        None

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Scan Determination**
            - This scanner provides a inital determination on a file if it is infected or not based on the
              the ClamAV signature database.

    ## Known Limitations
    !!! warning "Known Limitations"
        - **ClamAV Signature Database**
            - This scanner relies on the ClamAV signature database which is not necesarily all-encompassing. Though
              the scanner may return a determination, users should be advise that this is not exaustive.

    ## To Do
    !!! question "To Do"
        - The ClamAV signature database is currently pulled every scan as a POC. This could be converted to a
          signature pull on a cadence, such as every 24 hours.

    ## References
    !!! quote "References"
    - [ClamAV Documentation Source](https://docs.clamav.net/Introduction.html)
    - [BlogPost on ClamAV Scanner](https://simovits.com/strelka-let-us-build-a-scanner/)

    ## Contributors
    !!! example "Contributors"
        - [Sara Kalupa](https://github.com/skalupa)

    """

    def scan(self, data, file, options, expire_at):
        try:
            # Check if ClamAV package is installed
            if not shutil.which("clamscan"):
                self.flags.append("clamav_not_installed_error")
                return
        except Exception as e:
            self.flags.append(str(e))
            return

        try:
            with tempfile.NamedTemporaryFile(dir="/tmp/", mode="wb") as tmp_data:
                tmp_data.write(data)
                tmp_data.flush()
                tmp_data.seek(0)

                # Run freshclam to gret the newest database signatures
                stdout, stderr = subprocess.Popen(
                    ["freshclam"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate(timeout=self.scanner_timeout)

                temp_log = tempfile.NamedTemporaryFile(dir="/tmp/", mode="wb")
                loglocation = "--log=" + temp_log.name

                # Run the actual ClamAV scan and report to local temp log file
                process = subprocess.Popen(
                    ["clamscan", "--disable-cache", loglocation, tmp_data.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, stderr = process.communicate()

                with open(temp_log.name, "r") as file:
                    for line in file:
                        if ":" in line:
                            # Attempt to split out scan information
                            splitline = line.split(":")
                            self.event[splitline[0]] = splitline[1].strip()
                        else:
                            continue

        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("clamAV_Scan_process_error")
            raise
        finally:
            # Ensure that tempfile gets closed out if there are any issues
            tmp_data.close()
