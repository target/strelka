import datetime
import io
import os

import rarfile

from strelka import strelka

HOST_OS_MAPPING = {
    0: "RAR_OS_MSDOS",
    1: "RAR_OS_OS2",
    2: "RAR_OS_WIN32",
    3: "RAR_OS_UNIX",
    4: "RAR_OS_MACOS",
    5: "RAR_OS_BEOS",
}

rarfile.UNRAR_TOOL = "unrar"
rarfile.PATH_SEP = "/"


class ScanRar(strelka.Scanner):
    """Extracts files from RAR archives.

    Attributes:
        password: List of passwords to use when bruteforcing encrypted files.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
        password_file: Location of passwords file for rar archives.
            Defaults to /etc/strelka/passwords.dat
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

        with io.BytesIO(data) as rar_io:
            try:
                with rarfile.RarFile(rar_io, part_only=True) as rar_obj:
                    # If any file in the archive is encrypted, set a flag
                    if (
                        rar_obj.needs_password()
                        and "password_protected" not in self.flags
                    ):
                        self.flags.append("password_protected")

                    # If filename encryption is enabled, set a flag
                    if (
                        rar_obj.needs_password()
                        and len(list(rar_obj.infolist())) == 0
                        and "encrypted_filenames" not in self.flags
                    ):
                        self.flags.append("encrypted_filenames")

                    # If filename encryption is enabled, attempt to recover the password
                    if (
                        crack_pws
                        and self.passwords
                        and len(list(rar_obj.infolist())) == 0
                    ):
                        for password in self.passwords:
                            try:
                                # Re-instantiate rarfile to address password change behavior
                                rar_obj = rarfile.RarFile(rar_io, part_only=True)
                                rar_obj.setpassword(
                                    password.decode("utf-8") if password else None
                                )

                                if list(rar_obj.infolist()):
                                    self.passwords.insert(
                                        0,
                                        self.passwords.pop(
                                            self.passwords.index(password)
                                        ),
                                    )

                                    break
                            except rarfile.RarWrongPassword:
                                pass
                            except rarfile.PasswordRequired:
                                pass
                            except rarfile.BadRarFile:
                                pass

                        if (
                            len(list(rar_obj.infolist())) == 0
                            and "no_password_match_found" not in self.flags
                        ):
                            self.flags.append("no_password_match_found")

                    if rar_obj.comment:
                        self.event["comment"] = rar_obj.comment

                    filelist = rar_obj.infolist()

                    # Count the file entries, in case the function encounters an unhandled exception
                    for compressed_file in filelist:
                        if compressed_file.is_dir():
                            continue
                        self.event["total"]["files"] += 1

                    # For each file in rar, gather metadata and pass extracted file back to Strelka
                    for i, name in enumerate(filelist):
                        if not name.isdir():
                            extract = True
                            extracted = False
                            compression_rate = 0

                            try:
                                extract_data = b""
                                compressed_file = rar_obj.getinfo(name)

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

                                self.event["host_os"] = HOST_OS_MAPPING[
                                    compressed_file.host_os
                                ]

                                try:
                                    rar_data_io = rar_obj.open(
                                        compressed_file, mode="r"
                                    )
                                    if rar_data_io.readable():
                                        extract_data = rar_data_io.readall()
                                except Exception:
                                    try:
                                        # rar_obj = rarfile.RarFile(rar_io, part_only=True)
                                        rar_data_io = rar_obj.open(
                                            compressed_file,
                                            mode="r",
                                            pwd="",
                                        )
                                        if rar_data_io.readable():
                                            extract_data = rar_data_io.readall()

                                    except Exception:
                                        if "password_protected" not in self.flags:
                                            self.flags.append("password_protected")

                                        for password in self.passwords:
                                            try:
                                                # rar_obj = rarfile.RarFile(rar_io, part_only=True)
                                                rar_data_io = rar_obj.open(
                                                    compressed_file,
                                                    mode="r",
                                                    pwd=(
                                                        password.decode("utf-8")
                                                        if password
                                                        else None
                                                    ),
                                                )
                                                if rar_data_io.readable():
                                                    extract_data = rar_data_io.readall()
                                                    self.passwords.insert(
                                                        0,
                                                        self.passwords.pop(
                                                            self.passwords.index(
                                                                password
                                                            )
                                                        ),
                                                    )
                                                    if (
                                                        password
                                                        and crack_pws
                                                        and log_pws
                                                    ):
                                                        if (
                                                            "password"
                                                            not in self.event.keys()
                                                        ):
                                                            self.event["password"] = []
                                                        if password.decode(
                                                            "utf-8"
                                                        ) not in self.event.get(
                                                            "password", []
                                                        ):
                                                            self.event[
                                                                "password"
                                                            ].append(
                                                                password.decode("utf-8")
                                                            )
                                                    break
                                            except (
                                                RuntimeError,
                                                rarfile.RarCRCError,
                                                rarfile.RarWrongPassword,
                                                rarfile.BadRarFile,
                                                rarfile.PasswordRequired,
                                            ):
                                                pass

                                # If we're cracking passwords, a file was encrypted, but failed to decrypt, set a flag
                                if (
                                    crack_pws
                                    and compressed_file.needs_password()
                                    and not extract_data
                                    and "no_password_match_found" not in self.flags
                                ):
                                    self.flags.append("no_password_match_found")

                                # If there's data in it, and no limits have been met, emit the file
                                if extract_data and extract:
                                    # Send extracted file back to Strelka
                                    self.emit_file(
                                        extract_data, name=f"{compressed_file.filename}"
                                    )

                                    extracted = True

                                if not (
                                    limit_metadata
                                    and self.event["total"]["extracted"] >= file_limit
                                ):
                                    self.event["files"].append(
                                        {
                                            "file_name": compressed_file.filename,
                                            "datetime": compressed_file.mtime.isoformat(),
                                            "ctime": (
                                                compressed_file.ctime.isoformat()
                                                if isinstance(
                                                    compressed_file.ctime,
                                                    datetime.datetime,
                                                )
                                                else None
                                            ),
                                            "mtime": (
                                                compressed_file.mtime.isoformat()
                                                if isinstance(
                                                    compressed_file.mtime,
                                                    datetime.datetime,
                                                )
                                                else None
                                            ),
                                            "atime": (
                                                compressed_file.atime.isoformat()
                                                if isinstance(
                                                    compressed_file.atime,
                                                    datetime.datetime,
                                                )
                                                else None
                                            ),
                                            "file_size": compressed_file.file_size,
                                            "compression_size": compressed_file.compress_size,
                                            "compression_rate": round(
                                                compression_rate, 2
                                            ),
                                            "extracted": extracted,
                                            "encrypted": compressed_file.needs_password(),
                                        }
                                    )

                                if extracted:
                                    self.event["total"]["extracted"] += 1

                            except NotImplementedError:
                                self.flags.append("unsupport_compression")
                            except RuntimeError:
                                self.flags.append("runtime_error")
                            except ValueError:
                                self.flags.append("value_error")

            except rarfile.BadRarFile:
                self.flags.append("bad_rar")
                raise

            # Top level compression metric
            if file_size_total > 0 and compress_size_total > 0:
                size_difference_total = file_size_total - compress_size_total
                self.event["compression_rate"] = round(
                    (size_difference_total * 100.0) / file_size_total, 2
                )
            else:
                self.event["compression_rate"] = 0.00
