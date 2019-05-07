import io
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


class ScanRar(strelka.Scanner):
    """Extracts files from RAR archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, data, file, options, expire_at):
        file_limit = options.get('limit', 1000)

        self.event['total'] = {'files': 0, 'extracted': 0}

        with io.BytesIO(data) as rar_io:
            with rarfile.RarFile(rar_io) as rf:
                rf_info_list = rf.infolist()
                self.event['total']['files'] = len(rf_info_list)
                for rf_object in rf_info_list:
                    if not rf_object.isdir():
                        if self.event['total']['extracted'] >= file_limit:
                            break

                        file_info = rf.getinfo(rf_object)
                        if not file_info.needs_password():
                            self.event['host_os'] = HOST_OS_MAPPING[file_info.host_os]

                            extract_file = strelka.File(
                                name=f'{file_info.filename}',
                                source=self.name,
                            )

                            for c in strelka.chunk_string(rf.read(rf_object)):
                                self.upload_to_cache(
                                    extract_file.pointer,
                                    c,
                                    expire_at,
                                )

                            self.files.append(extract_file)
                            self.event['total']['extracted'] += 1

                        else:
                            self.flags.append('password_protected')
