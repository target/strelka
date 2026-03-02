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

        # استخراج uuid_part من اسم الفايل
        name = str(getattr(file, "name", "") or "")
        if "___" in name:
            uuid_part, _ = name.split("___", 1)
        else:
            uuid_part = "unknown/ScanTar"

        with io.BytesIO(data) as tar_io:
            try:
                with tarfile.open(fileobj=tar_io) as tar_obj:
                    tar_members = tar_obj.getmembers()

                    # عدّ الملفات (غير الفولدرات)
                    for tar_member in tar_members:
                        if not tar_member.isdir():
                            self.event["total"]["files"] += 1

                    # استخراج الملفات
                    for index, tar_member in enumerate(tar_members):
                        if not tar_member.isfile():
                            continue

                        if self.event["total"]["extracted"] >= file_limit:
                            break

                        try:
                            tar_file = tar_obj.extractfile(tar_member)
                            if tar_file is not None:
                                file_bytes = tar_file.read()

                                emitted_name = f"{uuid_part}___file_{index}"

                                self.emit_file(file_bytes, name=emitted_name)

                                self.event["total"]["extracted"] += 1

                        except KeyError:
                            self.flags.append("key_error")

            except tarfile.ReadError:
                self.flags.append("tarfile_read_error")