import json
import logging
import os
import shutil
import subprocess
import tempfile

from strelka import strelka


class ScanPcap(strelka.Scanner):
    """Extract files from pcap/pcapng files.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, data, file, options, expire_at):
        file_limit = options.get("limit", 1000)
        tmp_directory = options.get("tmp_file_directory", "/tmp/")
        scanner_timeout = options.get("scanner_timeout", 120)

        self.event["total"] = {"files": 0, "extracted": 0}
        self.event["files"] = []

        try:
            # Check if zeek package is installed
            if not shutil.which("zeek"):
                self.flags.append("zeek_not_installed_error")
                return
        except Exception as e:
            self.flags.append(e)

        with tempfile.NamedTemporaryFile(dir=tmp_directory, mode="wb") as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()
            tmp_data.seek(0)

            with tempfile.TemporaryDirectory() as tmp_extract:

                try:
                    (stdout, stderr) = subprocess.Popen(
                        ["zeek",
                         "-r",
                         tmp_data.name,
                         "/opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek",
                         f"FileExtract::prefix={tmp_extract}",
                         "LogAscii::use_json=T"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=tmp_extract
                    ).communicate(timeout=scanner_timeout)

                    if os.path.exists(os.path.join(tmp_extract, "files.log")):
                        with open(os.path.join(tmp_extract, "files.log"), "r") as json_file:

                            # files.log is one JSON object per line, convert to array
                            file_events = json.loads("[" + ",".join(json_file.read().splitlines()) + "]")

                            for file_event in file_events:

                                if self.event["total"]["extracted"] >= file_limit:
                                    self.flags.append("pcap_file_limit_error")
                                    break

                                self.event["total"]["files"] += 1
                                self.event["files"].append(file_event)

                                extracted_file_path = os.path.join(tmp_extract, file_event["extracted"])

                                try:
                                    if os.path.exists(extracted_file_path):
                                        logging.debug(f"size_seen {file_event['seen_bytes']}")
                                        self.upload(extracted_file_path, expire_at)
                                        self.event["total"]["extracted"] += 1

                                except strelka.ScannerTimeout:
                                    raise
                                except Exception:
                                    self.flags.append("zeek_file_upload_error")
                    else:
                        self.flags.append("zeek_no_file_log")

                except strelka.ScannerTimeout:
                    raise
                except Exception:
                    self.flags.append("zeek_extract_process_error")

    def upload(self, name, expire_at):
        """Send extracted file to coordinator"""
        with open(name, "rb") as extracted_file:
            extract_file = strelka.File(
                source=self.name,
            )

            for c in strelka.chunk_string(extracted_file.read()):
                self.upload_to_coordinator(
                    extract_file.pointer,
                    c,
                    expire_at,
                )
                self.files.append(extract_file)
