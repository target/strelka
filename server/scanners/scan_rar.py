import io
import rarfile

from server import lib

HOST_OS_MAPPING = {
    0: 'RAR_OS_MSDOS',
    1: 'RAR_OS_OS2',
    2: 'RAR_OS_WIN32',
    3: 'RAR_OS_UNIX',
    4: 'RAR_OS_MACOS',
    5: 'RAR_OS_BEOS'
}


class ScanRar(lib.StrelkaScanner):
    """Extracts files from RAR archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, file_object, options):
        file_limit = options.get('limit', 1000)

        self.metadata['total'] = {'files': 0, 'extracted': 0}

        with io.BytesIO(file_object.data) as rar_object:
            with rarfile.RarFile(rar_object) as rf:
                rf_info_list = rf.infolist()
                self.metadata['total']['files'] = len(rf_info_list)
                for rf_object in rf_info_list:
                    if not rf_object.isdir():
                        if self.metadata['total']['extracted'] >= file_limit:
                            break

                        child_file = rf.read(rf_object)
                        child_info = rf.getinfo(rf_object)
                        if not child_info.needs_password():
                            rar_metadata = {'scanRarHostOs': HOST_OS_MAPPING[child_info.host_os]}
                            child_filename = f'{self.scanner_name}::{child_info.filename}'
                            child_fo = lib.StrelkaFile(data=child_file,
                                                       filename=child_filename,
                                                       depth=file_object.depth + 1,
                                                       parent_uid=file_object.uid,
                                                       root_uid=file_object.root_uid,
                                                       parent_hash=file_object.hash,
                                                       root_hash=file_object.root_hash,
                                                       source=self.scanner_name)
                            child_fo.add_ext_metadata(rar_metadata)
                            self.children.append(child_fo)
                            self.metadata['total']['extracted'] += 1
                        else:
                            file_object.flags.append(f'{self.scanner_name}::password_protected')
