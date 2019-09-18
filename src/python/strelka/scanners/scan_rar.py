import io
import os
import rarfile

from strelka import strelka


HOST_OS_MAPPING = {
    0: 'RAR_OS_MSDOS',
    1: 'RAR_OS_OS2',
    2: 'RAR_OS_WIN32',
    3: 'RAR_OS_UNIX',
    4: 'RAR_OS_MACOS',
    5: 'RAR_OS_BEOS',
}

rarfile.UNRAR_TOOL = "unrar"
rarfile.PATH_SEP= '/'

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
        file_limit = options.get('limit', 1000)
        password_file = options.get('password_file', '/etc/strelka/passwords.dat')

        self.event['total'] = {'files': 0, 'extracted': 0}

        if not self.passwords:
            if os.path.isfile(password_file):
                with open(password_file, 'rb') as f:
                    for line in f:
                        self.passwords.append(line.strip())

        with io.BytesIO(data) as rar_io:
            try:
                with rarfile.RarFile(rar_io) as rar_obj:
                    rf_info_list = rar_obj.infolist()
                    self.event['total']['files'] = len(rf_info_list)

                    password = ''
                    for rf_object in rf_info_list:
                        if not rf_object.isdir():
                            if self.event['total']['extracted'] >= file_limit:
                                break

                            try:
                                extract_data = b''
                                file_info = rar_obj.getinfo(rf_object)
                                self.event['host_os'] = HOST_OS_MAPPING[file_info.host_os]

                                if not file_info.needs_password():
                                    extract_data = rar_obj.read(rf_object)
                                else:
                                    if not 'password_protected' in self.flags:
                                        self.flags.append('password_protected')  
                                    
                                    if not password:
                                        for pw in self.passwords:
                                            try:
                                                extract_data = rar_obj.read(rf_object, pw.decode('utf-8'))
                                                if extract_data:
                                                    self.event['password'] = pw.decode('utf-8')
                                                    break
                                            except (RuntimeError, rarfile.BadRarFile):
                                                pass
                                    else:
                                        extract_data = rar_obj.read(rf_object, password)

                                    if not extract_data and not 'no_password_match_found' in self.flags:
                                        self.flags.append('no_password_match_found')
                                              

                                if extract_data:
                                    extract_file = strelka.File(
                                        name=f'{file_info.filename}',
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
                                self.flags.append('unsupport_compression')
                            except RuntimeError:
                                self.flags.append('runtime_error')
                            except ValueError:
                                self.flags.append('value_error')
         
            except rarfile.BadRarFile:
                self.flags.append('bad_rar')