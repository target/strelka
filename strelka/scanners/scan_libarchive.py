import libarchive
import uuid

from strelka import core
from strelka.scanners import util


class ScanLibarchive(core.StrelkaScanner):
    """Extracts files from libarchive-compatible archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, st_file, options):
        file_limit = options.get('limit', 1000)

        self.metadata['total'] = {'files': 0, 'extracted': 0}

        try:
            with libarchive.memory_reader(self.data) as archive:
                for entry in archive:
                    self.metadata['total']['files'] += 1
                    if entry.isfile:
                        if self.metadata['total']['extracted'] >= file_limit:
                            continue

                        ex_name = ''
                        if entry.pathname:
                            ex_name = f'{entry.pathname}'

                        ex_file = core.StrelkaFile(
                            name=ex_name,
                            source=self.name,
                        )
                        for block in entry.get_blocks():
                            p = self.fk.pipeline()
                            p.rpush(ex_file.uid, block)
                            p.expire(ex_file.uid, self.expire)
                            p.execute()
                        self.files.append(ex_file)

                        self.metadata['total']['extracted'] += 1

        except libarchive.ArchiveError:
            self.flags.add('libarchive_archive_error')
