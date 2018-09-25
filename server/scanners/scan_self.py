from server import objects


class ScanSelf(objects.StrelkaScanner):
    """Collects metadata from the file's internal attributes.

    This scanners logs metadata that was defined during the creation of a
    file or metadata that provides basic information (e.g. file size) about
    a file.
    """
    def scan(self, file_object, options):
        self.metadata["location"] = file_object.location
        self.metadata["filename"] = file_object.filename
        self.metadata["depth"] = file_object.depth
        self.metadata["uid"] = file_object.uid
        self.metadata["parentUid"] = file_object.parent_uid
        self.metadata["rootUid"] = file_object.root_uid
        self.metadata["hash"] = file_object.hash
        self.metadata["parentHash"] = file_object.parent_hash
        self.metadata["rootHash"] = file_object.root_hash
        self.metadata["source"] = file_object.source
        self.metadata["scannerList"] = file_object.scanner_list
        self.metadata["size"] = file_object.size
        if self.metadata["location"] and self.metadata["size"] == 0:
            file_object.flags.append(f"{self.scanner_name}::file_retrieval_failed")
