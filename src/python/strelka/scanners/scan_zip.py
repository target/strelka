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
        file_limit = options.get('limit', 100)
        password_file = options.get('password_file', '/etc/strelka/passwords.dat')
        passwords = []

        # Gather count and list of files to be extracted
        self.event['total'] = {'files': 0, 'extracted': 0}
        self.event['files'] = []

        # Temporary top level compression metrics
        compress_size_total = 0
        file_size_total = 0

        if os.path.isfile(password_file):
            with open(password_file, 'rb') as f:
                for line in f:
                    passwords.append(line.strip())

        with io.BytesIO(data) as zip_io:
            try:
                with zipfile.ZipFile(zip_io) as zip_obj:
                    filelist = zip_obj.filelist
                    self.event['total']['files'] = len(filelist)

                    # For each file in zip, gather metadata metrics and pass back to Strelka for recursive extraction.
                    for i, name in enumerate(filelist):
                        if name.file_size > 0 and name.compress_size > 0:

                            compress_size_total += name.compress_size
                            file_size_total += name.file_size

                            size_difference = name.file_size - name.compress_size
                            compression_rate = (size_difference * 100.0) / name.file_size
                            self.event['files'].append({
                                "file_name": name.filename,
                                "file_size": name.file_size,
                                "compression_size": name.compress_size,
                                "compression_rate": round(compression_rate, 2)
                            })

                            if self.event['total']['extracted'] >= file_limit:
                                break

                            try:
                                extract_data = b''
                                zinfo = zip_obj.getinfo(name.filename)

                                if zinfo.flag_bits & 0x1:
                                    if i == 0:
                                        self.flags.append('encrypted')

                                        if passwords:
                                            for pw in passwords:
                                                try:
                                                    extract_data = zip_obj.read(name.filename, pw)
                                                    self.event['password'] = pw

                                                except (RuntimeError, zipfile.BadZipFile, zlib.error):
                                                    pass
                                else:
                                    extract_data = zip_obj.read(name.filename)

                                if extract_data:
                                    extract_file = strelka.File(
                                        name=name.filename,
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

                    # Top level compression metric
                    size_difference_total = file_size_total - compress_size_total
                    self.event['compression_rate'] = round((size_difference_total * 100.0) / file_size_total, 2)

            except zipfile.BadZipFile:
                self.flags.append('bad_zip')
