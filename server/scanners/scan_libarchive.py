import libarchive

from server import objects


class ScanLibarchive(objects.StrelkaScanner):
    """Extracts files from libarchive-compatible archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, file_object, options):
        file_limit = options.get("limit", 1000)

        self.metadata["total"] = {"files": 0, "extracted": 0}

        try:
            with libarchive.memory_reader(file_object.data) as archive:
                for entry in archive:
                    self.metadata["total"]["files"] += 1
                    if entry.isfile:
                        if self.metadata["total"]["extracted"] >= file_limit:
                            continue

                        child_file = b"".join(entry.get_blocks())
                        if entry.pathname:
                            child_filename = f"{self.scanner_name}::{entry.pathname}"
                        else:
                            child_filename = f"{self.scanner_name}::size_{len(child_file)}"
                        child_fo = objects.StrelkaFile(data=child_file,
                                                       filename=child_filename,
                                                       depth=file_object.depth + 1,
                                                       parent_uid=file_object.uid,
                                                       root_uid=file_object.root_uid,
                                                       parent_hash=file_object.hash,
                                                       root_hash=file_object.root_hash,
                                                       source=self.scanner_name)
                        self.children.append(child_fo)
                        self.metadata["total"]["extracted"] += 1

        except libarchive.ArchiveError:
            file_object.flags.append(f"{self.scanner_name}::libarchive_archive_error")
