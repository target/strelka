import libarchive
import uuid

from strelka import core


class ScanLibarchive(core.StrelkaScanner):
    """Extracts files from libarchive-compatible archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, data, file_object, options):
        file_limit = options.get('limit', 1000)

        self.metadata['total'] = {'files': 0, 'extracted': 0}

        try:
            with libarchive.memory_reader(data) as archive:
                for entry in archive:
                    self.metadata['total']['files'] += 1
                    if entry.isfile:
                        if self.metadata['total']['extracted'] >= file_limit:
                            continue

                        file_data = b''.join(entry.get_blocks())
                        file_name = ''
                        if entry.pathname:
                            file_name = f'{entry.pathname}'

                        file_ = core.StrelkaFile(
                            name=file_name,
                            source=self.scanner_name,
                        )
                        self.r0.setex(
                            file_.uid,
                            self.expire,
                            file_data,
                        )
                        self.files.append(file_)
                        self.metadata['total']['extracted'] += 1

        except libarchive.ArchiveError:
            self.flags.add(f'{self.scanner_name}::libarchive_archive_error')
