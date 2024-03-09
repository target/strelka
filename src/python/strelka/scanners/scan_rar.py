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

    def init(self, options):
        self.passwords = []

    def scan(self, data, file, options, expire_at):
        file_limit = options.get("limit", 1000)
        password_file = options.get("password_file", "/etc/strelka/passwords.dat")

        self.event["total"] = {"files": 0, "extracted": 0}

        if not self.passwords:
            if os.path.isfile(password_file):
                with open(password_file, "rb") as f:
                    for line in f:
                        self.passwords.append(line.strip())

        with io.BytesIO(data) as rar_io:
            try:
                with rarfile.RarFile(rar_io) as rar_obj:
                    rf_info_list = rar_obj.infolist()
                    for info in rf_info_list:
                        if info.is_file():
                            self.event["total"]["files"] += 1

                    password = ""
                    for i, name in enumerate(rf_info_list):
                        if not name.isdir():
                            if self.event["total"]["extracted"] >= file_limit:
                                break

                            try:
                                extract_data = b""
                                file_info = rar_obj.getinfo(name)
                                self.event["host_os"] = HOST_OS_MAPPING[
                                    file_info.host_os
                                ]

                                if not file_info.needs_password():
                                    extract_data = rar_obj.read(name)
                                else:
                                    if i == 0:
                                        self.flags.append("password_protected")

                                    if not password and i == 0:
                                        for pw in self.passwords:
                                            try:
                                                data = rar_obj.open(
                                                    name,
                                                    mode="r",
                                                    pwd=pw.decode("utf-8"),
                                                )
                                                if data.readable():
                                                    extract_data = data.readall()
                                                    password = pw.decode("utf-8")
                                                    self.event["password"] = pw.decode(
                                                        "utf-8"
                                                    )
                                                    break
                                            except (
                                                RuntimeError,
                                                rarfile.BadRarFile,
                                                rarfile.RarCRCError,
                                                rarfile.RarWrongPassword,
                                            ):
                                                pass
                                    elif not password and i > 0:
                                        break
                                    else:
                                        try:
                                            data = rar_obj.open(
                                                name, mode="r", pwd=password
                                            )
                                            if data.readable():
                                                extract_data = data.readall()
                                        except (
                                            RuntimeError,
                                            rarfile.BadRarFile,
                                            rarfile.RarCRCError,
                                            rarfile.RarWrongPassword,
                                        ):
                                            pass

                                if (
                                    not extract_data
                                    and "no_password_match_found" not in self.flags
                                ):
                                    self.flags.append("no_password_match_found")

                                if extract_data:
                                    # Send extracted file back to Strelka
                                    self.emit_file(
                                        extract_data, name=f"{file_info.filename}"
                                    )

                                    self.event["total"]["extracted"] += 1

                            except NotImplementedError:
                                self.flags.append("unsupport_compression")
                            except RuntimeError:
                                self.flags.append("runtime_error")
                            except ValueError:
                                self.flags.append("value_error")

            except rarfile.BadRarFile:
                self.flags.append("bad_rar")
