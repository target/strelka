import io
import os
import zipfile
import zlib

import uuid
from strelka import core


class ScanZip(core.StrelkaScanner):
    """Extracts files from ZIP archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
        password_file: Location of passwords file for zip archives.
            Defaults to /etc/strelka/passwords.txt.
    """
    def init(self):
        self.rainbow_table = []

    def scan(self, data, file_object, options):
        file_limit = options.get('limit', 1000)
        password_file = options.get('password_file', '/etc/strelka/passwords.txt')

        self.metadata['total'] = {'files': 0, 'extracted': 0}

        try:
            if not self.rainbow_table:
                if os.path.isfile(password_file):
                    with open(password_file, 'r+') as f:
                        for line in f:
                            self.rainbow_table.append(bytes(line.strip(), 'utf-8'))

        except IOError:
            self.flags.add(f'{self.scanner_name}::file_read_error')

        with io.BytesIO(data) as data:
            try:
                with zipfile.ZipFile(data) as zip:
                    name_list = zip.namelist()
                    self.metadata['total']['files'] = len(name_list)
                    for name in name_list:
                        if not name.endswith('/'):
                            if self.metadata['total']['extracted'] >= file_limit:
                                break

                            try:
                                file_data = None
                                zinfo = zip.getinfo(name)

                                if zinfo.flag_bits & 0x1 and self.rainbow_table:  # File is encrypted
                                    for pwd in self.rainbow_table:
                                        try:
                                            file_data = zip.read(name, pwd)

                                            if file_data is not None:
                                                self.flags.add(f'{self.scanner_name}::encrypted_archive_file')
                                                break
                                        except RuntimeError:
                                            pass

                                elif zinfo.flag_bits & 0x1 and not self.rainbow_table:  # File is encrypted, no passwords
                                    self.flags.add(f'{self.scanner_name}::no_archive_passwords')
                                    return
                                else:
                                    file_data = zip.read(name)

                                if file_data is not None:
                                    file_ = core.StrelkaFile(
                                        name=name,
                                        source=self.scanner_name,
                                    )
                                    self.r0.setex(
                                        file_.uid,
                                        self.expire,
                                        file_data,
                                    )
                                    self.files.append(file_)
                                    self.metadata['total']['extracted'] += 1

                            except NotImplementedError:
                                self.flags.add(f'{self.scanner_name}::unsupported_compression')
                            except RuntimeError:
                                self.flags.add(f'{self.scanner_name}::runtime_error')
                            except ValueError:
                                self.flags.add(f'{self.scanner_name}::value_error')
                            except zlib.error:
                                self.flags.add(f'{self.scanner_name}::zlib_error')

            except zipfile.BadZipFile:
                self.flags.add(f'{self.scanner_name}::bad_zip_file')
