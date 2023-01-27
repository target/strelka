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

    def scan(self, data, file, options, expire_at):
        file_limit = options.get("limit", 100)
        password_file = options.get("password_file", "/etc/strelka/passwords.dat")
        passwords = []

        # Gather count and list of files to be extracted
        self.event["total"] = {"files": 0, "extracted": 0}
        self.event["files"] = []

        # Temporary top level compression metrics
        compress_size_total = 0
        file_size_total = 0

        if os.path.isfile(password_file):
            with open(password_file, "rb") as f:
                for line in f:
                    passwords.append(line.strip())

        with io.BytesIO(data) as zip_io:
            try:

                is_aes = False
                with pyzipper.ZipFile(zip_io) as zip_obj:
                    filelist = zip_obj.filelist
                    for file in filelist:
                        if not file.is_dir():
                            # Check for the AES compression type
                            if file.compress_type == 99:
                                is_aes = True
                                break

                with pyzipper.ZipFile(zip_io) if is_aes else pyzipper.ZipFile(
                    zip_io
                ) as zip_obj:
                    filelist = zip_obj.filelist
                    for file in filelist:
                        if not file.is_dir():
                            self.event["total"]["files"] += 1

                    # For each file in zip, gather metadata metrics and pass back to Strelka for recursive extraction.
                    for i, name in enumerate(filelist):
                        if name.file_size > 0 and name.compress_size > 0:

                            compress_size_total += name.compress_size
                            file_size_total += name.file_size

                            size_difference = name.file_size - name.compress_size
                            compression_rate = (
                                size_difference * 100.0
                            ) / name.file_size
                            self.event["files"].append(
                                {
                                    "file_name": name.filename,
                                    "file_size": name.file_size,
                                    "compression_size": name.compress_size,
                                    "compression_rate": round(compression_rate, 2),
                                }
                            )

                            if self.event["total"]["extracted"] >= file_limit:
                                break

                            try:
                                extract_data = b""
                                zinfo = zip_obj.getinfo(name.filename)

                                if zinfo.flag_bits & 0x1:
                                    if "encrypted" not in self.flags:
                                        self.flags.append("encrypted")

                                    if passwords:
                                        for pw in passwords:
                                            try:
                                                extract_data = zip_obj.read(
                                                    name.filename, pw
                                                )
                                                self.event["password"] = pw.decode(
                                                    "utf-8"
                                                )

                                            except (
                                                RuntimeError,
                                                pyzipper.BadZipFile,
                                                zlib.error,
                                            ):
                                                pass
                                else:
                                    try:
                                        extract_data = zip_obj.read(name.filename)
                                    except RuntimeError:
                                        self.flags.append("runtime_error")
                                    except pyzipper.BadZipFile:
                                        self.flags.append("bad_zip")
                                    except zlib.error:
                                        self.flags.append("zlib_error")

                                # Suppress sending to coordinator in favor of ScanEncryptedZip
                                if extract_data and "encrypted" not in self.flags:

                                    # Send extracted file back to Strelka
                                    self.emit_file(extract_data, name=name.filename)

                                    self.event["total"]["extracted"] += 1

                            except NotImplementedError:
                                self.flags.append("unsupported_compression")
                            except RuntimeError:
                                self.flags.append("runtime_error")
                            except ValueError:
                                self.flags.append("value_error")
                            except zlib.error:
                                self.flags.append("zlib_error")

                    # Top level compression metric
                    size_difference_total = file_size_total - compress_size_total
                    self.event["compression_rate"] = round(
                        (size_difference_total * 100.0) / file_size_total, 2
                    )

            except pyzipper.BadZipFile:
                self.flags.append("bad_zip")
