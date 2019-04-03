import io
import tarfile

from strelka import core
from strelka.scanners import util


class ScanTar(core.StrelkaScanner):
    """Extract files from tar archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, st_file, options):
        file_limit = options.get('limit', 1000)

        self.metadata['total'] = {'files': 0, 'extracted': 0}

        with io.BytesIO(self.data) as tar_io:
            try:
                with tarfile.open(fileobj=tar_io) as tar:
                    tar_members = tar.getmembers()
                    self.metadata['total']['files'] = len(tar_members)
                    for tar_member in tar_members:
                        if tar_member.isfile:
                            if self.metadata['total']['extracted'] >= file_limit:
                                break

                            try:
                                tar_file = tar.extractfile(tar_member)
                                if tar_file is not None:
                                    ex_name = ''
                                    if tar_member.name:
                                        ex_name = f'{tar_member.name}'

                                    ex_file = core.StrelkaFile(
                                        name=ex_name,
                                        source=self.name,
                                    )
                                    for c in util.chunk_string(tar_file.read()):
                                        p = self.fk.pipeline()
                                        p.rpush(ex_file.uid, c)
                                        p.expire(ex_file.uid, self.expire)
                                        p.execute()
                                    self.files.append(ex_file)

                                    self.metadata['total']['extracted'] += 1

                            except KeyError:
                                self.flags.add('key_error')

            except tarfile.ReadError:
                self.flags.add('tarfile_read_error')
