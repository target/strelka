import io
import logging
import os
import subprocess
import tempfile

import msoffcrypto

from strelka import strelka

# Set logging level to INFO to prevent passwords from getting logged
logging.getLogger("msoffcrypto").setLevel(logging.INFO)


def crack_word(
    self,
    data,
    jtr_path,
    tmp_dir,
    password_file,
    min_length=1,
    max_length=10,
    scanner_timeout=150,
    brute=False,
):
    try:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, mode="wb") as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            (office2john, stderr) = subprocess.Popen(
                [jtr_path + "office2john.py", tmp_data.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).communicate()

            if not office2john:
                self.flags.append("office2john_error")
                return

        with tempfile.NamedTemporaryFile(dir=tmp_dir) as tmp_data:
            tmp_data.write(office2john)
            tmp_data.flush()

            (stdout, stderr) = subprocess.Popen(
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
                    (stdout, stderr) = subprocess.Popen(
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
                    (stdout, stderr) = subprocess.Popen(
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


class ScanEncryptedDoc(strelka.Scanner):
    """Extracts passwords from encrypted office word documents.

    Attributes:
            passwords: List of passwords to use when bruteforcing encrypted files.

    Options:
            limit: Maximum number of files to extract.
                    Defaults to 1000.
            password_file: Location of passwords file for zip archives.
                    Defaults to /etc/strelka/passwords.dat.
    """

    def scan(self, data, file, options, expire_at):
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
