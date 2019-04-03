import io
import rarfile

from strelka import core
from strelka.scanners import util

HOST_OS_MAPPING = {
    0: 'RAR_OS_MSDOS',
    1: 'RAR_OS_OS2',
    2: 'RAR_OS_WIN32',
    3: 'RAR_OS_UNIX',
    4: 'RAR_OS_MACOS',
    5: 'RAR_OS_BEOS',
}


class ScanRar(core.StrelkaScanner):
    """Extracts files from RAR archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, st_file, options):
        file_limit = options.get('limit', 1000)

        self.metadata['total'] = {'files': 0, 'extracted': 0}

        with io.BytesIO(self.data) as rar_io:
            with rarfile.RarFile(rar_io) as rf:
                rf_info_list = rf.infolist()
                self.metadata['total']['files'] = len(rf_info_list)
                for rf_object in rf_info_list:
                    if not rf_object.isdir():
                        if self.metadata['total']['extracted'] >= file_limit:
                            break

                        file_info = rf.getinfo(rf_object)
                        if not file_info.needs_password():
                            self.metadata['hostOs'] = HOST_OS_MAPPING[file_info.host_os]

                            ex_file = core.StrelkaFile(
                                name=f'{file_info.filename}',
                                source=self.name,
                            )
                            for c in util.chunk_string(rf.read(rf_object)):
                                p = self.fk.pipeline()
                                p.rpush(ex_file.uid, c)
                                p.expire(ex_file.uid, self.expire)
                                p.execute()
                            self.files.append(ex_file)

                            self.metadata['total']['extracted'] += 1

                        else:
                            self.flags.add('password_protected')
