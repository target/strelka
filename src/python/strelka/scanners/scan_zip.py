import io
import os
import zipfile
import zlib

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
        file_limit = options.get('limit', 1000)

        self.event['total'] = {'files': 0, 'extracted': 0}

        with io.BytesIO(data) as zip_io:
            try:
                with zipfile.ZipFile(zip_io) as zip_obj:
                    name_list = zip_obj.namelist()
                    self.event['total']['files'] = len(name_list)

                    for i, name in enumerate(name_list):
                        if not name.endswith('/'):
                            if self.event['total']['extracted'] >= file_limit:
                                break

                            try:
                                extract_data = b''
                                zinfo = zip_obj.getinfo(name)

                                if zinfo.flag_bits & 0x1:
                                    if i == 0:
                                        self.flags.append('encrypted')

                                else:
                                    extract_data = zip_obj.read(name)

                                if extract_data:
                                    extract_file = strelka.File(
                                        name=name,
                                        source=self.name,
                                    )

                                    for c in strelka.chunk_string(extract_data):
                                        self.upload_to_coordinator(
                                            extract_file.pointer,
                                            c,
                                            expire_at,
                                        )

                                    self.files.append(extract_file)
                                    self.event['total']['extracted'] += 1

                            except NotImplementedError:
                                self.flags.append('unsupported_compression')
                            except RuntimeError:
                                self.flags.append('runtime_error')
                            except ValueError:
                                self.flags.append('value_error')
                            except zlib.error:
                                self.flags.append('zlib_error')

            except zipfile.BadZipFile:
                self.flags.append('bad_zip')
