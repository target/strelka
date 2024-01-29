import io
import os
import subprocess
import tempfile
import zlib

import pyzipper

from strelka import strelka


def crack_zip(
    self,
    data,
    jtr_path,
    tmp_dir,
    password_file,
    brute=False,
    max_length=10,
    scanner_timeout=150,
):
    try:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, mode="wb") as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            (zip2john, stderr) = subprocess.Popen(
                [jtr_path + "zip2john", tmp_data.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            ).communicate()

            if not zip2john:
                self.flags.append("zip2john_error")
                return

        with tempfile.NamedTemporaryFile(dir=tmp_dir) as tmp_data:
            tmp_data.write(zip2john)
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
                tmp_data.write(zip2john)
                tmp_data.flush()

                if os.path.isfile(password_file):
                    (stdout, stderr) = subprocess.Popen(
                        [jtr_path + "john", f"-w={password_file}", tmp_data.name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                    ).communicate(timeout=scanner_timeout)

                    # ZipCrypto
                    if b"PKZIP" in stdout.split(b"\n")[0]:
                        if stdout.split(b"\n")[1]:
                            self.flags.append("cracked_by_wordlist")
                            return stdout.split(b"\n")[1].split()[0]
                    # WinZip AES
                    elif b"WinZip" in stdout.split(b"\n")[0]:
                        if stdout.split(b"\n")[2]:
                            self.flags.append("cracked_by_wordlist")
                            return stdout.split(b"\n")[2].split()[0]
                if brute:
                    (stdout, stderr) = subprocess.Popen(
                        [
                            jtr_path + "john",
                            "--incremental=Alnum",
                            f"--max-length={max_length}",
                            f"--max-run-time={scanner_timeout}",
                            tmp_data.name,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                    ).communicate(timeout=scanner_timeout)
                    if stdout.split(b"\n")[1]:
                        self.flags.append("cracked_by_incremental")
                        return stdout.split(b"\n")[1].split()[0]
                return ""
        else:
            return stdout.split(b":")[1]

    except strelka.ScannerTimeout:
        raise
    except Exception as e:
        self.flags.append(str(e))
        return ""


class ScanEncryptedZip(strelka.Scanner):
    """Extracts passwords from encrypted ZIP archives.

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
        file_limit = options.get("limit", 1000)
        password_file = options.get("password_file", "/etc/strelka/passwords.dat")
        log_extracted_pws = options.get("log_pws", False)
        scanner_timeout = options.get("scanner_timeout", 150)
        brute = options.get("brute_force", False)
        max_length = options.get("max_length", 5)

        self.event["total"] = {"files": 0, "extracted": 0}

        with io.BytesIO(data) as zip_io:
            try:
                is_aes = False
                with pyzipper.ZipFile(zip_io) as zip_obj:
                    file_list = zip_obj.filelist  # .filelist
                    for file_list_item in file_list:
                        if not file_list_item.is_dir():
                            # Check for the AES compression type
                            if file_list_item.compress_type == 99:
                                is_aes = True
                                break

                with (
                    pyzipper.AESZipFile(zip_io) if is_aes else pyzipper.ZipFile(zip_io)
                ) as zip_obj:
                    file_list = zip_obj.filelist  # .filelist
                    for file_list_item in file_list:
                        if not file_list_item.is_dir():
                            self.event["total"]["files"] += 1

                    extracted_pw = crack_zip(
                        self,
                        data,
                        jtr_path,
                        tmp_directory,
                        brute=brute,
                        scanner_timeout=scanner_timeout,
                        max_length=max_length,
                        password_file=password_file,
                    )

                    if not extracted_pw:
                        self.flags.append("Could not extract password")
                        return

                    if log_extracted_pws:
                        self.event["cracked_password"] = extracted_pw

                    for file_item in file_list:
                        if not file_item.is_dir():
                            if self.event["total"]["extracted"] >= file_limit:
                                break

                            try:
                                extract_data = zip_obj.read(
                                    file_item.filename, pwd=extracted_pw
                                )

                                if extract_data:
                                    # Send extracted file back to Strelka
                                    self.emit_file(
                                        extract_data, name=file_item.filename
                                    )

                                    self.event["total"]["extracted"] += 1

                            except NotImplementedError:
                                self.flags.append("unsupported_compression")
                            except RuntimeError:
                                self.flags.append("runtime_error")
                            except ValueError:
                                self.flags.append("value_error")
                            except zlib.error:
                                self.flags.append("zlib_error")

            except pyzipper.BadZipFile:
                self.flags.append("bad_zip")
