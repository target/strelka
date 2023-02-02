import os
import re
import subprocess
import tempfile
import time

from strelka import strelka


def convert_unit_john(jtr_number: str) -> float:
    if jtr_number.endswith("K"):
        return float(jtr_number[:-1]) * 1000
    elif jtr_number.endswith("M"):
        return float(jtr_number[:-1]) * 1000000
    elif jtr_number.endswith("G"):
        return float(jtr_number[:-1]) * 1000000000
    elif jtr_number.endswith("T"):
        return float(jtr_number[:-1]) * 1000000000000
    else:
        return float(jtr_number)


def office2john(data: bytes, tmp_dir: str) -> bytes:
    try:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, mode="wb") as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            (stdout, stderr) = subprocess.Popen(
                ["/jtr/office2john.py", tmp_data.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()

    except strelka.ScannerTimeout:
        raise
    except Exception:
        return b""

    return stdout


def zip2john(data: bytes, tmp_dir: str) -> bytes:
    try:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, mode="wb") as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            (stdout, stderr) = subprocess.Popen(
                ["/jtr/zip2john.py", tmp_data.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()

    except strelka.ScannerTimeout:
        raise
    except Exception:
        return b""

    return stdout


def sevenzip2john(data: bytes, tmp_dir: str) -> bytes:
    try:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, mode="wb") as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            (stdout, stderr) = subprocess.Popen(
                ["/jtr/7z2john.pl", tmp_data.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()

    except strelka.ScannerTimeout:
        raise
    except Exception:
        return b""

    return stdout


def crack_john(
    self,
    jtr_path: str,
    tmp_dir: str,
    hashes: bytes,
    password_file: str,
    min_length: int = 1,
    max_length: int = 6,
    scanner_timeout: int = 150,
    brute: bool = False,
) -> bytes:
    re_statistics = re.compile(
        rb"(?P<gps>\d+(\.\d+)?[KMGT]?)g/s (?P<pps>\d+(\.\d+)?[KMGT]?)p/s (?P<cps>\d+(\.\d+)?[KMGT]?)c/s (?P<ccps>\d+(\.\d+)?[KMGT]?)C/s"
    )

    re_password = re.compile(rb"(?P<password>[^\s]+)\s+\(tmp\w+\)")
    re_password_pot = re.compile(rb"tmp\w+:(?P<password>[^\s]+)")

    with tempfile.NamedTemporaryFile(dir=tmp_dir) as tmp_data:
        tmp_data.write(hashes)
        tmp_data.flush()

        (stdout, stderr) = subprocess.Popen(
            [jtr_path + "john", "--show", tmp_data.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()

        if not stdout:
            self.flags.append("jtr_show_error")
            return b""

        # No cracked hashes cached
        if b"0 password hashes cracked" in stdout:
            self.flags.append("wordlist")
            if os.path.isfile(password_file):
                (stdout, stderr) = subprocess.Popen(
                    [jtr_path + "john", f"-w={password_file}", tmp_data.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate(timeout=scanner_timeout)

                for line in stdout.splitlines():
                    if match := re_password.match(line):
                        self.flags.append("cracked_by_wordlist")
                        return match.group("password")
            else:
                self.flags.append("wordlist_file_missing")

            if brute:
                self.flags.append("incremental")
                brute_time_start = time.time()
                (stdout, stderr) = subprocess.Popen(
                    [
                        jtr_path + "john",
                        "--incremental=Alnum",
                        f"--min-length={min_length}",
                        f"--max-length={max_length}",
                        f"--max-run-time={scanner_timeout - 5}",
                        tmp_data.name,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).communicate(timeout=scanner_timeout)

                brute_time_end = time.time()

                hashes_per_second = 0.0

                for statistic in re_statistics.finditer(stderr):
                    hashes_per_second = convert_unit_john(
                        statistic.group("ccps").decode("utf-8")
                    )

                self.event["performance"] = {
                    "keyspace": {
                        "min_length": min_length,
                        "max_length": max_length,
                    },
                    "elapsed_seconds_wall": brute_time_end - brute_time_start,
                    "hashes_per_second": hashes_per_second,
                }

                for line in stdout.splitlines():
                    if match := re_password.match(line):
                        self.flags.append("cracked_by_incremental")
                        return match.group("password")

            return b""
        else:
            match = re_password_pot.match(stdout)
            if match and match.group("password"):
                return match.group("password")
            else:
                return b""
