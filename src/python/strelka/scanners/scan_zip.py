import io
import os
import zlib

import pyzipper

from strelka import strelka


class ScanZip(strelka.Scanner):
    """Extracts files from ZIP archives.

    Attributes:
        passwords: List of passwords to use when bruteforcing encrypted files.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
        password_file: Location of passwords file for zip archives.
            Defaults to /etc/strelka/passwords.dat.
    """

    def init(self):
        self.passwords = []

    def scan(self, data, file, options, expire_at):
        file_limit = options.get("limit", 100)
        size_limit = options.get("size_limit", 250000000)
        limit_metadata = options.get("limit_metadata", True)
        crack_pws = options.get("crack_pws", False)
        log_pws = options.get("log_pws", True)
        password_file = options.get("password_file", "/etc/strelka/passwords.dat")

        # Gather count and list of files to be extracted
        self.event["total"] = {"files": 0, "extracted": 0}
        self.event["files"] = []

        # Temporary top level compression metrics
        compress_size_total = 0
        file_size_total = 0

        if crack_pws:
            if not self.passwords:
                if os.path.isfile(password_file):
                    with open(password_file, "rb") as f:
                        for line in f:
                            self.passwords.append(line.strip())

                    if (
                        len(self.passwords) == 0
                        and "no_passwords_loaded" not in self.flags
                    ):
                        self.flags.append("no_passwords_loaded")
                else:
                    if "password_file_missing" not in self.flags:
                        self.flags.append("password_file_missing")

        self.passwords.insert(0, None)

        with io.BytesIO(data) as zip_io:
            try:
                with pyzipper.AESZipFile(zip_io) as zip_obj:
                    filelist = zip_obj.filelist

                    # Count the file entries, in case the function encounters an unhandled exception
                    for compressed_file in filelist:
                        if compressed_file.is_dir():
                            continue
                        self.event["total"]["files"] += 1

                    # For each file in zip, gather metadata and pass extracted file back to Strelka
                    for compressed_file in filelist:
                        if compressed_file.is_dir():
                            continue

                        extract = True
                        extracted = False
                        compression_rate = 0

                        if compressed_file.file_size > size_limit:
                            extract = False
                            if "file_size_limit" not in self.flags:
                                self.flags.append("file_size_limit")

                        if self.event["total"]["extracted"] >= file_limit:
                            extract = False
                            if "file_count_limit" not in self.flags:
                                self.flags.append("file_count_limit")

                        if (
                            compressed_file.file_size > 0
                            and compressed_file.compress_size > 0
                        ):
                            compress_size_total += compressed_file.compress_size
                            file_size_total += compressed_file.file_size

                            size_difference = (
                                compressed_file.file_size
                                - compressed_file.compress_size
                            )
                            compression_rate = (
                                size_difference * 100.0
                            ) / compressed_file.file_size

                        try:
                            extract_data = b""
                            zinfo = zip_obj.getinfo(compressed_file.filename)

                            if zinfo.flag_bits & 0x1:
                                if "encrypted" not in self.flags:
                                    self.flags.append("encrypted")

                            for password in self.passwords:
                                try:
                                    if extract:
                                        extract_data = zip_obj.read(
                                            compressed_file.filename, password
                                        )
                                        if extract_data:
                                            self.passwords.insert(
                                                0,
                                                self.passwords.pop(
                                                    self.passwords.index(password)
                                                ),
                                            )
                                            if password and crack_pws and log_pws:
                                                if "password" not in self.event.keys():
                                                    self.event["password"] = []
                                                if password.decode(
                                                    "utf-8"
                                                ) not in self.event.get("password", []):
                                                    self.event["password"].append(
                                                        password.decode("utf-8")
                                                    )
                                            break
                                except RuntimeError:
                                    pass

                            # If there's data in it, and no limits have been met, emit the file
                            if extract_data and extract:
                                # Send extracted file back to Strelka
                                self.emit_file(
                                    extract_data, name=compressed_file.filename
                                )
                                extracted = True

                            if not (
                                limit_metadata
                                and self.event["total"]["extracted"] >= file_limit
                            ):
                                self.event["files"].append(
                                    {
                                        "file_name": compressed_file.filename,
                                        "file_size": compressed_file.file_size,
                                        "compression_size": compressed_file.compress_size,
                                        "compression_rate": round(compression_rate, 2),
                                        "extracted": extracted,
                                        "encrypted": (
                                            True
                                            if zinfo.flag_bits & 0x1 == 1
                                            else False
                                        ),
                                    }
                                )

                            if extracted:
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
                            self.flags.append("bad_zip_file")

                        # Top level compression metric
                        if file_size_total > 0 and compress_size_total > 0:
                            size_difference_total = (
                                file_size_total - compress_size_total
                            )
                            self.event["compression_rate"] = round(
                                (size_difference_total * 100.0) / file_size_total, 2
                            )
                        else:
                            self.event["compression_rate"] = 0.00

            except pyzipper.BadZipFile:
                self.flags.append("bad_zip_file")
            except ValueError:
                self.flags.append("value_error")
