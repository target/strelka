import os
import pathlib
import re
import shutil
import subprocess
import tempfile

from strelka import strelka

from .common import password_cracking


class PasswordProtectedException(Exception):
    pass


class ScanSevenZip(strelka.Scanner):
    """Extracts files from 7zip archives"""

    EXCLUDED_ROOT_DIRS: list[str] = []

    def scan(self, data: bytes, file: strelka.File, options: dict, expire_at) -> None:
        file_limit = options.get("limit", 100)
        tmp_directory = options.get("tmp_file_directory", "/tmp/")
        scanner_timeout = options.get("scanner_timeout", 150)
        password_file = options.get("password_file", "/etc/strelka/passwords.dat")
        log_extracted_pws = options.get("log_pws", False)
        brute = options.get("brute_force", False)
        min_length = options.get("min_length", 1)
        max_length = options.get("max_length", 5)
        crack_pws = options.get("crack_pws", True)

        self.event["total"] = {"files": 0, "extracted": 0}
        self.event["files"] = []
        self.event["hidden_dirs"] = []
        self.event["meta"] = {}

        extracted_pw = ""

        with tempfile.NamedTemporaryFile(dir=tmp_directory, mode="wb") as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()
            tmp_data.seek(0)

            if not tmp_data:
                self.flags.append("7zip_tmp_error")
                return

            (stdout, stderr) = subprocess.Popen(
                ["7zz", "l", tmp_data.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate(timeout=scanner_timeout)

            if crack_pws and self.parse_7zip_password(stdout.decode("utf-8")):
                sevenzip2john = password_cracking.sevenzip2john(data, tmp_directory)
                if not sevenzip2john:
                    self.flags.append("7z2john_output_empty")
                    return

                extracted_pw = password_cracking.crack_john(
                    self,
                    "/jtr/",
                    tmp_directory,
                    hashes=sevenzip2john,
                    password_file=password_file,
                    min_length=min_length,
                    max_length=max_length,
                    scanner_timeout=scanner_timeout,
                    brute=brute,
                )

                if not extracted_pw:
                    self.flags.append("Could not extract password")
                    return

                if log_extracted_pws:
                    self.event["cracked_password"] = extracted_pw

            if extracted_pw:
                self.extract_7zip(
                    data,
                    tmp_directory,
                    scanner_timeout,
                    expire_at,
                    file_limit,
                    password=extracted_pw.decode("utf-8"),
                )
            else:
                self.extract_7zip(
                    data, tmp_directory, scanner_timeout, expire_at, file_limit
                )

    def extract_7zip(
        self, data, tmp_dir, scanner_timeout, expire_at, file_limit, password=""
    ):
        """Decompress input file to /tmp with 7zz, send files to coordinator"""

        # Check if 7zip package is installed
        if not shutil.which("7zz"):
            self.flags.append("7zip_not_installed_error")
            return

        with tempfile.NamedTemporaryFile(dir=tmp_dir, mode="wb") as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()
            tmp_data.seek(0)

            if not tmp_data:
                self.flags.append("7zip_tmp_error")
                return

            with tempfile.TemporaryDirectory() as tmp_extract:
                if password:
                    (stdout, stderr) = subprocess.Popen(
                        [
                            "7zz",
                            "x",
                            tmp_data.name,
                            f"-o{tmp_extract}",
                            f"-p{password}",
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate(timeout=scanner_timeout)
                else:
                    (stdout, stderr) = subprocess.Popen(
                        ["7zz", "x", tmp_data.name, f"-o{tmp_extract}"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ).communicate(timeout=scanner_timeout)

                def get_all_items(root, exclude=None):
                    """Iterates through filesystem paths"""
                    if exclude is None:
                        exclude = []
                    for item in root.iterdir():
                        if item.name in exclude:
                            continue
                        yield item
                        if item.is_dir():
                            yield from get_all_items(item)

                # Iterate over extracted files, except excluded paths
                for name in get_all_items(
                    pathlib.Path(tmp_extract), self.EXCLUDED_ROOT_DIRS
                ):
                    if not name.is_file():
                        continue

                    if self.event["total"]["extracted"] >= file_limit:
                        self.flags.append("file_limit_error")
                        break

                    relname = os.path.relpath(name, tmp_extract)
                    with open(name, "rb") as extracted_file:
                        # Send extracted file back to Strelka
                        self.emit_file(extracted_file.read(), name=relname)

                    self.event["total"]["extracted"] += 1

            if password:
                (stdout, stderr) = subprocess.Popen(
                    ["7zz", "l", tmp_data.name, f"-p{password}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate(timeout=scanner_timeout)
            else:
                (stdout, stderr) = subprocess.Popen(
                    ["7zz", "l", tmp_data.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate(timeout=scanner_timeout)
            self.parse_7zip_stdout(stdout.decode("utf-8"), file_limit)

    def parse_7zip_password(self, output_7zip):
        # Method = LZMA2:14 7zAES
        regex_method = re.compile(
            r"Method = (?P<compression>[^ ]+) ?(?P<encryption>.*)"
        )

        # Enter password (will not be echoed):
        regex_pompt = re.compile(r"(?P<prompt>Enter password)")

        output_lines = output_7zip.splitlines()

        for output_line in output_lines:
            # Method property
            match = regex_method.match(output_line)
            if match and match.group("encryption"):
                return True

            # Password prompt
            match = regex_pompt.match(output_line)
            if match:
                return True

        return False

    def parse_7zip_stdout(self, output_7zip, file_limit):
        """Parse 7zz output, create metadata"""

        mode = None

        output_lines = output_7zip.splitlines()

        # 7-Zip (z) 24.09 (x64) : Copyright (c) 1999-2021 Igor Pavlov : 2021-12-26
        regex_7zip_version = re.compile(r"^7-Zip[^\d]+(\d+\.\d+)")

        # --/----
        regex_mode_properties = re.compile(r"^(--|----)$")

        # Comment =
        # regex_property = re.compile(r"^(.+) = (.+)$")

        #    Date      Time    Attr         Size   Compressed  Name
        regex_mode_files = re.compile(
            r"\s+Date\s+Time\s+Attr\s+Size\s+Compressed\s+Name"
        )

        # 2022-12-05 17:23:59 ....A       100656       102400  lorem.txt
        regex_file = re.compile(
            r"(?:(?P<datetime>\d+-\d+-\d+\s\d+:\d+:\d+)\s*)?(?P<modes>[A-Z.]{5})(?:\s+(?P<size>\d+))?(?:\s+(?P<compressed>\d+))?\s+(?P<name>.+)"
        )

        def parse_file_modes(file_modes):
            file_mode_list = []

            for file_mode in file_modes:
                if file_mode == "D":
                    file_mode_list.append("directory")
                elif file_mode == "R":
                    file_mode_list.append("readonly")
                elif file_mode == "H":
                    file_mode_list.append("hidden")
                elif file_mode == "S":
                    file_mode_list.append("system")
                elif file_mode == "A":
                    file_mode_list.append("archivable")

            return file_mode_list

        partition = {}

        for output_line in output_lines:
            if output_line:
                # Properties section
                match = regex_mode_properties.match(output_line)
                if match:
                    if "path" in partition.keys():
                        if not self.event.get("meta", {}).get("partitions", []):
                            self.event["meta"]["partitions"] = []
                        self.event["meta"]["partitions"].append(partition)
                    partition = {}
                    mode = "properties"

                # File section
                match = regex_mode_files.match(output_line)
                if match:
                    # Wrap up final partition
                    if "path" in partition.keys():
                        if not self.event.get("meta", {}).get("partitions", []):
                            self.event["meta"]["partitions"] = []
                        self.event["meta"]["partitions"].append(partition)
                    partition = {}
                    mode = "files"

                # Header section
                if not mode:
                    match = regex_7zip_version.match(output_line)
                    if match:
                        version = regex_7zip_version.match(output_line).group(1)
                        self.event["meta"]["7zip_version"] = version

                        continue

                elif mode == "files":
                    match = regex_file.search(output_line)
                    if match:
                        modes_list = parse_file_modes(match.group("modes"))

                        # Skip excluded paths
                        if (
                            os.path.normpath(match.group("name")).split(os.path.sep)[0]
                            in self.EXCLUDED_ROOT_DIRS
                        ):
                            continue

                        # Matching ScanIso, collecting hidden directories separately
                        if "hidden" in modes_list and "directory" in modes_list:
                            self.event["hidden_dirs"].append(match.group("name"))

                        if "directory" not in modes_list:
                            self.event["total"]["files"] += 1
                            file_info = {
                                "filename": match.group("name"),
                                "size": match.group("size"),
                            }
                            if match.group("datetime") is not None:
                                file_info["datetime"] = match.group("datetime")
                            self.event["files"].append(file_info)
