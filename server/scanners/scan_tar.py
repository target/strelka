import io
import tarfile

from server import objects


class ScanTar(objects.StrelkaScanner):
    """Extract files from tar archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """
    def scan(self, file_object, options):
        file_limit = options.get("limit", 1000)

        self.metadata["total"] = {"files": 0, "extracted": 0}

        with io.BytesIO(file_object.data) as tar_object:
            try:
                with tarfile.open(fileobj=tar_object) as tar_file:
                    tar_members = tar_file.getmembers()
                    self.metadata["total"]["files"] = len(tar_members)
                    for tar_member in tar_members:
                        if tar_member.isfile:
                            if self.metadata["total"]["extracted"] >= file_limit:
                                break

                            try:
                                extract_file = tar_file.extractfile(tar_member)
                                if extract_file is not None:
                                    child_file = extract_file.read()
                                    if tar_member.name:
                                        child_filename = f"{self.scanner_name}::{tar_member.name}"
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

                            except KeyError:
                                file_object.flags.append(f"{self.scanner_name}::key_error")

            except tarfile.ReadError:
                file_object.flags.append(f"{self.scanner_name}::tarfile_read_error")
