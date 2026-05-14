import io
import logging
import os
import subprocess
import tempfile
from typing import Optional

import msoffcrypto

from strelka import strelka

# Set logging level to INFO to prevent passwords from getting logged
logging.getLogger("msoffcrypto").setLevel(logging.INFO)


class ScanEncryptedDoc(strelka.Scanner):
    """
    Attempts to decrypt and extract content from encrypted Microsoft Office Word documents.

    This scanner uses John the Ripper (JtR) to crack the password of encrypted Word documents and then
    attempts to decrypt and extract their content. It supports using a predefined wordlist or brute-force
    approach for cracking passwords.

    Scanner Type: Collection

    Attributes:
        None

    Other Parameters:
        jtr_path (str): Path to the John the Ripper executable. Defaults to '/jtr/'.
        tmp_file_directory (str): Temporary directory path for file extraction. Defaults to '/tmp/'.
        password_file (str): Location of the password file for Word documents. Defaults to '/etc/strelka/passwords.dat'.
        log_pws (bool): Log cracked passwords if set to True. Defaults to False.
        scanner_timeout (int): Timeout for each attempt of cracking in seconds. Defaults to 150.
        brute_force (bool): Use brute force method if set to True. Defaults to False.
        max_length (int): Maximum length for brute-force password generation. Defaults to 7.
        passwords: List of passwords to use when brute-forcing encrypted files.

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Deobfuscate/Decode Files or Information**
            - Decrypts and extracts content from encrypted Word documents for further analysis.

    ## Known Limitations
    !!! warning "Known Limitations"
        - **Resource Intensive**
            - Password cracking can be resource-intensive and time-consuming. No support for external cracking.
        - **Password Complexity**
            - Has a password complexity limit. May not successfully crack highly complex passwords, especially without a relevant wordlist.

    ## To Do
    !!! question "To Do"
        - **Enhanced Cracking Implementation**
            - Integrate more advanced password cracking techniques. Perhaps passing this off to a dedicated cracker.

    ## References
    !!! quote "References"
        - [John the Ripper tool](https://www.openwall.com/john/)

    ## Contributors
    !!! example "Contributors"
        - [Derek Thomas](https://github.com/Derekt2)
        - [Paul Hutelmyer](https://github.com/phutelmyer)
        - [Ryan O'Horo](https://github.com/ryanohoro)
        - [Nate Icart](https://github.com/nateicart)

    """

    def scan(
        self, data: bytes, file: strelka.File, options: dict, expire_at: int
    ) -> None:
        """
        Scans an encrypted Word document, attempting to crack the encryption password and extract its contents.

        Args:
            data (bytes): The file data to be scanned.
            file (strelka.File): The file object containing metadata.
            options (dict): Scanner options.
            expire_at (int): Expiry time of the scan.
        """
        jtr_path = options.get("jtr_path", "/jtr/")
        tmp_directory = options.get("tmp_file_directory", "/tmp/")
        password_file = options.get("password_file", "/etc/strelka/passwords.dat")
        log_extracted_pws = options.get("log_pws", False)
        scanner_timeout = options.get("scanner_timeout", 150)
        brute = options.get("brute_force", False)
        max_length = options.get("max_length", 7)

        with io.BytesIO(data) as doc_io:
            msoff_doc = msoffcrypto.OfficeFile(doc_io)
            output_doc = io.BytesIO()
            if extracted_pw := crack_word(
                self,
                data,
                jtr_path,
                tmp_directory,
                brute=brute,
                scanner_timeout=scanner_timeout,
                max_length=max_length,
                password_file=password_file,
            ):
                if log_extracted_pws:
                    self.event["cracked_password"] = extracted_pw
                try:
                    msoff_doc.load_key(password=extracted_pw.decode("utf-8"))
                    msoff_doc.decrypt(output_doc)
                    output_doc.seek(0)
                    extract_data = output_doc.read()
                    output_doc.seek(0)

                    # Send extracted file back to Strelka
                    self.emit_file(extract_data)

                except strelka.ScannerTimeout:
                    raise
                except Exception:
                    self.flags.append(
                        "Could not decrypt document with recovered password"
                    )

            else:
                self.flags.append("Could not extract password")


def crack_word(
    self,
    data: bytes,
    jtr_path: str,
    tmp_dir: str,
    password_file: str,
    min_length: int = 1,
    max_length: int = 10,
    scanner_timeout: int = 150,
    brute: bool = False,
) -> Optional[str]:
    """
    Attempts to crack the password of an encrypted Word document using John the Ripper.

    This function uses the office2john tool to extract the hash from the encrypted document and then
    employs John the Ripper to crack the password. It supports both wordlist and brute-force methods.

    Args:
        data (bytes): The content of the encrypted Word document.
        jtr_path (str): Path to the directory containing the John the Ripper executable and office2john.py.
        tmp_dir (str): Directory to store temporary files during processing.
        password_file (str): Path to the file containing potential passwords.
        min_length (int): Minimum password length for brute-force attempts. Default is 1.
        max_length (int): Maximum password length for brute-force attempts. Default is 10.
        scanner_timeout (int): Timeout in seconds for each cracking attempt. Default is 150.
        brute (bool): Indicates whether to use brute-force method. Default is False.

    Returns:
        Optional[str]: The cracked password if successful, None otherwise.
    """
    try:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, mode="wb") as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            office2john, stderr = subprocess.Popen(
                ["python3", jtr_path + "office2john.py", tmp_data.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).communicate()

            if not office2john:
                self.flags.append("office2john_error")
                return

        with tempfile.NamedTemporaryFile(dir=tmp_dir) as tmp_data:
            tmp_data.write(office2john)
            tmp_data.flush()

            stdout, stderr = subprocess.Popen(
                [jtr_path + "john", "--show", tmp_data.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).communicate()

            if not stdout:
                self.flags.append("jtr_show_error")
                return

        if b"0 password hashes cracked" in stdout:
            with tempfile.NamedTemporaryFile(dir=tmp_dir) as tmp_data:
                tmp_data.write(office2john)
                tmp_data.flush()

                if os.path.isfile(password_file):
                    stdout, stderr = subprocess.Popen(
                        [jtr_path + "john", f"-w={password_file}", tmp_data.name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                    ).communicate(timeout=scanner_timeout)

                    if b"oldoffice" in stdout.split(b"\n")[0]:
                        if stdout.split(b"\n")[2]:
                            self.flags.append("cracked_by_wordlist")
                            return stdout.split(b"\n")[2].split()[0]
                    elif b"Office" in stdout.split(b"\n")[0]:
                        if stdout.split(b"\n")[3]:
                            self.flags.append("cracked_by_wordlist")
                            return stdout.split(b"\n")[3].split()[0]

                if brute:
                    stdout, stderr = subprocess.Popen(
                        [
                            jtr_path + "john",
                            "--incremental=Alnum",
                            f"--min-length={min_length}",
                            f"--max-length={max_length}",
                            f"--max-run-time={scanner_timeout}",
                            tmp_data.name,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                    ).communicate(timeout=scanner_timeout + 5)

                    if b"oldoffice" in stdout.split(b"\n")[0]:
                        if stdout.split(b"\n")[2]:
                            self.flags.append("cracked_by_incremental")
                            return stdout.split(b"\n")[2].split()[0]
                    elif b"Office" in stdout.split(b"\n")[0]:
                        if stdout.split(b"\n")[3]:
                            self.flags.append("cracked_by_incremental")
                            return stdout.split(b"\n")[3].split()[0]

                return ""
        else:
            return stdout.split(b":")[1].split()[0]
    except strelka.ScannerTimeout:
        raise
    except Exception as e:
        self.flags.append(str(e))
        return ""
    finally:
        # Ensure tempfile is closed even after error is thrown
        tmp_data.close()
