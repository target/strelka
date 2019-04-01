import io
import tarfile

from strelka import core


class ScanTar(core.StrelkaScanner):
    """Extract files from tar archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, data, file_object, options):
        file_limit = options.get('limit', 1000)

        self.metadata['total'] = {'files': 0, 'extracted': 0}

        with io.BytesIO(data) as data:
            try:
                with tarfile.open(fileobj=data) as tar:
                    tar_members = tar.getmembers()
                    self.metadata['total']['files'] = len(tar_members)
                    for tar_member in tar_members:
                        if tar_member.isfile:
                            if self.metadata['total']['extracted'] >= file_limit:
                                break

                            try:
                                extract_file = tar.extractfile(tar_member)
                                if extract_file is not None:
                                    file_name = ''
                                    if tar_member.name:
                                        file_name = f'{tar_member.name}'
                                    file_ = core.StrelkaFile(
                                        name=file_name,
                                        source=self.scanner_name,
                                    )
                                    self.r0.setex(
                                        file_.uid,
                                        self.expire,
                                        extract_file.read(),
                                    )
                                    self.files.append(file_)
                                    self.metadata['total']['extracted'] += 1

                            except KeyError:
                                self.flags.add(f'{self.scanner_name}::key_error')

            except tarfile.ReadError:
                self.flags.add(f'{self.scanner_name}::tarfile_read_error')
