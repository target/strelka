import io
import tarfile

from strelka import strelka


class ScanTar(strelka.Scanner):
    """Extract files from tar archives.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """

    def scan(self, data, file, options, expire_at):
        file_limit = options.get("limit", 1000)

        self.event["total"] = {"files": 0, "extracted": 0}

        with io.BytesIO(data) as tar_io:
            try:
                with tarfile.open(fileobj=tar_io) as tar_obj:
                    tar_members = tar_obj.getmembers()
                    for tar_member in tar_members:
                        if not tar_member.isdir():
                            self.event["total"]["files"] += 1
                    for tar_member in tar_members:
                        if tar_member.isfile():
                            if self.event["total"]["extracted"] >= file_limit:
                                break

                            try:
                                tar_file = tar_obj.extractfile(tar_member)
                                if tar_file is not None:
                                    # Send extracted file back to Strelka
                                    self.emit_file(
                                        tar_file.read(), name=tar_member.name
                                    )

                                    self.event["total"]["extracted"] += 1

                            except KeyError:
                                self.flags.append("key_error")

            except tarfile.ReadError:
                self.flags.append("tarfile_read_error")
