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
        size_limit = options.get("size_limit", 250000000)
        limit_metadata = options.get("limit_metadata", False)
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

                    # Count the file entries, in case the function encounters an unhandled exception
                    for file in filelist:
                        if file.is_dir():
                            continue
                        self.event["total"]["files"] += 1

                    # For each file in zip, gather metadata and pass extracted file back to Strelka
                    for file in filelist:
                        if file.is_dir():
                            continue

                        extract = True
                        extracted = False
                        compression_rate = 0

                        if file.file_size > 0 and file.compress_size > 0:
                            compress_size_total += file.compress_size
                            file_size_total += file.file_size

                            size_difference = file.file_size - file.compress_size
                            compression_rate = (
                                size_difference * 100.0
                            ) / file.file_size

                        try:
                            extract_data = b""
                            zinfo = zip_obj.getinfo(file.filename)

                            if zinfo.flag_bits & 0x1:
                                #  If it's encrypted, don't extract file to coordinator, let ScanEncryptedZip do it instead
                                extract = False
                                if "encrypted" not in self.flags:
                                    self.flags.append("encrypted")

                                if passwords:
                                    for pw in passwords:
                                        try:
                                            extract_data = zip_obj.read(
                                                file.filename, pw
                                            )
                                            self.event["password"] = pw.decode("utf-8")

                                        except (
                                            RuntimeError,
                                            pyzipper.BadZipFile,
                                            zlib.error,
                                        ):
                                            pass
                            else:
                                try:
                                    extract_data = zip_obj.read(file.filename)
                                except RuntimeError:
                                    self.flags.append("runtime_error")
                                except pyzipper.BadZipFile:
                                    self.flags.append("bad_zip_file")
                                except zlib.error:
                                    self.flags.append("zlib_error")

                            if file.file_size > size_limit:
                                extract = False
                                if "file_size_limit" not in self.flags:
                                    self.flags.append("file_size_limit")

                            if self.event["total"]["extracted"] >= file_limit:
                                extract = False
                                if "file_count_limit" not in self.flags:
                                    self.flags.append("file_count_limit")

                            # If there's data in it, and no limits have been met, emit the file
                            if extract_data and extract:
                                # Send extracted file back to Strelka
                                self.emit_file(extract_data, name=file.filename)
                                extracted = True

                            if not (
                                limit_metadata
                                and self.event["total"]["extracted"] >= file_limit
                            ):
                                self.event["files"].append(
                                    {
                                        "file_name": file.filename,
                                        "file_size": file.file_size,
                                        "compression_size": file.compress_size,
                                        "compression_rate": round(compression_rate, 2),
                                        "extracted": extracted,
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

                    # Top level compression metric
                    if file_size_total > 0 and compress_size_total > 0:
                        size_difference_total = file_size_total - compress_size_total
                        self.event["compression_rate"] = round(
                            (size_difference_total * 100.0) / file_size_total, 2
                        )
                    else:
                        self.event["compression_rate"] = 0.00

            except pyzipper.BadZipFile:
                self.flags.append("bad_zip_file")
            except ValueError:
                self.flags.append("value_error")
