import libarchive

from strelka import strelka


class ScanLibarchive(strelka.Scanner):
    """Extracts files from libarchive-compatible archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, data, file, options, expire_at):
        file_limit = options.get('limit', 1000)

        self.event['total'] = {'files': 0, 'extracted': 0}

        try:
            with libarchive.memory_reader(data) as archive:
                # Using basically the same logic to count files
                # However, it is more technically correct to count
                # the files before trying to extract them in case an error occurs
                for entry in archive:
                    if entry.isfile:
                        self.event['total']['files'] += 1

                for entry in archive:
                    if entry.isfile:
                        if self.event['total']['extracted'] >= file_limit:
                            continue

                        extract_file = strelka.File(
                            name=entry.pathname,
                            source=self.name,
                        )

                        for block in entry.get_blocks():
                            self.upload_to_coordinator(
                                extract_file.pointer,
                                block,
                                expire_at,
                            )

                        self.files.append(extract_file)
                        self.event['total']['extracted'] += 1

        except libarchive.ArchiveError:
            self.flags.append('libarchive_archive_error')
