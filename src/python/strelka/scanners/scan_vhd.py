import os
import pathlib
import re
import shutil
import subprocess
import tempfile

from strelka import strelka


class ScanVhd(strelka.Scanner):
    """Extracts files from VHD/VHDX images"""

    EXCLUDED_ROOT_DIRS = ["[SYSTEM]"]

    def scan(self, data, file, options, expire_at):
        file_limit = options.get("limit", 100)
        tmp_directory = options.get("tmp_file_directory", "/tmp/")
        scanner_timeout = options.get("scanner_timeout", 150)

        self.event["total"] = {"files": 0, "extracted": 0}
        self.event["files"] = []
        self.event["hidden_dirs"] = []
        self.event["meta"] = {}

        try:
            self.extract_7zip(
                data, tmp_directory, scanner_timeout, expire_at, file_limit
            )

        except Exception:
            self.flags.append("vhd_7zip_extract_error")

    def extract_7zip(self, data, tmp_dir, scanner_timeout, expire_at, file_limit):
        """Decompress input file to /tmp with 7zz"""

        # Check if 7zip package is installed
        if not shutil.which("7zz"):
            self.flags.append("vhd_7zip_not_installed_error")
            return

        with tempfile.TemporaryDirectory() as tmp_extract:

            with tempfile.NamedTemporaryFile(dir=tmp_dir, mode="wb") as tmp_data:
                tmp_data.write(data)
                tmp_data.flush()
                tmp_data.seek(0)

                if tmp_data:

                    try:
                        (stdout, stderr) = subprocess.Popen(
                            ["7zz", "x", tmp_data.name, f"-o{tmp_extract}"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
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
                            if name.is_file():
                                if self.event["total"]["extracted"] >= file_limit:
                                    break
                                self.event["total"]["extracted"] += 1

                                with open(name, "rb") as extracted_file:
                                    extract_file = strelka.File(
                                        source=self.name,
                                    )

                                    # Send extracted file to coordinator
                                    for c in strelka.chunk_string(
                                        extracted_file.read()
                                    ):
                                        self.upload_to_coordinator(
                                            extract_file.pointer,
                                            c,
                                            expire_at,
                                        )

                    except Exception:
                        self.flags.append("vhd_7zip_extract_error")
                        return

                    try:
                        (stdout, stderr) = subprocess.Popen(
                            ["7zz", "l", tmp_data.name],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                        ).communicate(timeout=scanner_timeout)

                        self.parse_7zip_stdout(stdout.decode("utf-8"), file_limit)

                    except Exception:
                        self.flags.append("vhd_7zip_output_error")
                        return

    def parse_7zip_stdout(self, output_7zip, file_limit):
        """Parse 7zz output, create metadata"""

        # Ubuntu
        # jammy (22.04LTS) (utils): 7-Zip file archiver with a high compression ratio [universe]
        # 21.07+dfsg-4: amd64 arm64 armhf ppc64el s390x
        # kinetic (utils): 7-Zip file archiver with a high compression ratio [universe]
        # 22.01+dfsg-2: amd64 arm64 armhf ppc64el s390x

        _7ZIP_MIN_VERSION = 21.07

        mode = None

        try:
            output_lines = output_7zip.splitlines()

            # 7-Zip (z) 22.01 (x64) : Copyright (c) 1999-2022 Igor Pavlov : 2022-07-15
            regex_7zip_version = re.compile(r"^7-Zip[^\d]+(\d+\.\d+)")

            # --/----
            regex_mode_properties = re.compile(r"^(--|----)$")

            # Comment =
            regex_property = re.compile(r"^(.+) = (.+)$")

            #    Date      Time    Attr         Size   Compressed  Name
            regex_mode_files = re.compile(
                r"\s+Date\s+Time\s+Attr\s+Size\s+Compressed\s+Name"
            )

            # 2022-12-05 17:23:59 ....A       100656       102400  lorem.txt
            regex_file = re.compile(
                r"(?P<datetime>\d+-\d+-\d+\s\d+:\d+:\d+)\s+(?P<modes>[A-Z.]{5})(?:\s+(?P<size>\d+))?(?:\s+(?P<compressed>\d+))?\s+(?P<name>.+)"
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
                            if not self.event.get("meta", {}).get("paritions", []):
                                self.event["meta"]["paritions"] = []
                            self.event["meta"]["paritions"].append(partition)
                        partition = {}
                        mode = "properties"

                    # File section
                    match = regex_mode_files.match(output_line)
                    if match:
                        # Wrap up final partition
                        if "path" in partition.keys():
                            if not self.event.get("meta", {}).get("paritions", []):
                                self.event["meta"]["paritions"] = []
                            self.event["meta"]["paritions"].append(partition)
                        partition = {}
                        mode = "files"

                    # Header section
                    if not mode:

                        match = regex_7zip_version.match(output_line)
                        if match:
                            version = regex_7zip_version.match(output_line).group(1)

                            # Check returned 7zip version for compatibility
                            if float(version) < _7ZIP_MIN_VERSION:
                                return

                            continue

                    elif mode == "properties":

                        # Collect specific properties
                        match = regex_property.match(output_line)
                        if match:

                            if match.group(1) == "Label":
                                partition["label"] = match.group(2)
                            elif match.group(1) == "Path":
                                partition["path"] = match.group(2)
                            elif match.group(1) == "Type":
                                partition["type"] = match.group(2)
                            elif match.group(1) == "Created":
                                partition["created"] = match.group(2)
                            elif match.group(1) == "Creator Application":
                                partition["creator_application"] = match.group(2)
                            elif match.group(1) == "File System":
                                partition["file_system"] = match.group(2)

                    elif mode == "files":
                        match = regex_file.match(output_line)
                        if match:
                            modes_list = parse_file_modes(match.group("modes"))

                            # Skip excluded paths
                            if (
                                os.path.normpath(match.group("name")).split(
                                    os.path.sep
                                )[0]
                                in self.EXCLUDED_ROOT_DIRS
                            ):
                                continue

                            # Matching ScanIso, collecting hidden directories separately
                            if "hidden" in modes_list and "directory" in modes_list:
                                self.event["hidden_dirs"].append(match.group("name"))

                            if "directory" not in modes_list:
                                if self.event["total"]["extracted"] >= file_limit:
                                    break
                                self.event["total"]["files"] += 1
                                self.event["files"].append(
                                    {
                                        "filename": match.group("name"),
                                        "size": match.group("size"),
                                        "datetime": match.group("datetime"),
                                    }
                                )

        except Exception:
            self.flags.append("vhd_7zip_parse_error")
            return
