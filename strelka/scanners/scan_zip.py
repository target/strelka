import io
import os
import zipfile
import zlib

import uuid
from strelka import core
from strelka.scanners import util


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

    def scan(self, st_file, options):
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
            self.flags.add('file_read_error')

        with io.BytesIO(self.data) as zip_io:
            try:
                with zipfile.ZipFile(zip_io) as zip:
                    name_list = zip.namelist()
                    self.metadata['total']['files'] = len(name_list)
                    for name in name_list:
                        if not name.endswith('/'):
                            if self.metadata['total']['extracted'] >= file_limit:
                                break

                            try:
                                ex_data = None
                                zinfo = zip.getinfo(name)

                                if zinfo.flag_bits & 0x1 and self.rainbow_table:  # File is encrypted
                                    for pwd in self.rainbow_table:
                                        try:
                                            ex_data = zip.read(name, pwd)

                                            if ex_data is not None:
                                                self.flags.add('encrypted_archive_file')
                                                break
                                        except RuntimeError:
                                            pass

                                elif zinfo.flag_bits & 0x1 and not self.rainbow_table:  # File is encrypted, no passwords
                                    self.flags.add('no_archive_passwords')
                                    return
                                else:
                                    ex_data = zip.read(name)

                                if ex_data is not None:
                                    ex_file = core.StrelkaFile(
                                        name=name,
                                        source=self.name,
                                    )
                                    for c in util.chunk_string(ex_data):
                                        p = self.fk.pipeline()
                                        p.rpush(ex_file.uid, c)
                                        p.expire(ex_file.uid, self.expire)
                                        p.execute()
                                    self.files.append(ex_file)

                                    self.metadata['total']['extracted'] += 1

                            except NotImplementedError:
                                self.flags.add('unsupported_compression')
                            except RuntimeError:
                                self.flags.add('runtime_error')
                            except ValueError:
                                self.flags.add('value_error')
                            except zlib.error:
                                self.flags.add('zlib_error')

            except zipfile.BadZipFile:
                self.flags.add('bad_zip_file')
