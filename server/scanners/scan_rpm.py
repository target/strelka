from datetime import datetime
import tempfile

import rpmfile

from server import objects


class ScanRpm(objects.StrelkaScanner):
    """Collects metadata and extracts files from RPM files.

    Options:
        tempfile_directory: Location where tempfile writes temporary files.
            Defaults to "/tmp/".
    """
    def scan(self, file_object, options):
        tempfile_directory = options.get("tempfile_directory", "/tmp/")

        with tempfile.NamedTemporaryFile(dir=tempfile_directory) as strelka_file:
            strelka_filename = strelka_file.name
            strelka_file.write(file_object.data)
            strelka_file.flush()

            try:
                with rpmfile.open(strelka_filename) as rpm_file:
                    child_file = file_object.data[rpm_file.data_offset:]
                    child_filename = f"{self.scanner_name}::size_{len(child_file)}"
                    for (key, value) in rpm_file.headers.items():
                        if key == "arch":
                            self.metadata["architecture"] = value
                        elif key == "archive_compression":
                            self.metadata["archiveCompression"] = value
                        elif key == "archive_format":
                            self.metadata["archiveFormat"] = value
                        elif key == "authors":
                            self.metadata["authors"] = value
                        elif key == "buildhost":
                            self.metadata["buildHost"] = value
                        elif key == "buildtime":
                            self.metadata["buildTime"] = datetime.utcfromtimestamp(value).isoformat(timespec="seconds")
                        elif key == "copyright":
                            self.metadata["copyright"] = value
                        elif key == "description":
                            self.metadata["description"] = value.replace(b"\n", b" ")
                        elif key == "filenames":
                            self.metadata["filenames"] = value
                        elif key == "group":
                            self.metadata["group"] = value
                        elif key == "name":
                            self.metadata["name"] = value
                            child_filename = f"{self.scanner_name}::{value.decode()}"
                        elif key == "os":
                            self.metadata["os"] = value
                        elif key == "packager":
                            self.metadata["packager"] = value
                        elif key == "provides":
                            self.metadata["provides"] = value
                        elif key == "release":
                            self.metadata["release"] = value
                        elif key == "requirename":
                            self.metadata["requireName"] = value
                        elif key == "rpmversion":
                            self.metadata["rpmVersion"] = value
                        elif key == "serial":
                            self.metadata["serial"] = value
                        elif key == "sourcerpm":
                            self.metadata["sourceRpm"] = value
                        elif key == "summary":
                            self.metadata["summary"] = value
                        elif key == "vendor":
                            self.metadata["vendor"] = value
                        elif key == "version":
                            self.metadata["version"] = value
                        elif key == "url":
                            self.metadata["url"] = value

                    child_fo = objects.StrelkaFile(data=child_file,
                                                   filename=child_filename,
                                                   depth=file_object.depth + 1,
                                                   parent_uid=file_object.uid,
                                                   root_uid=file_object.root_uid,
                                                   parent_hash=file_object.hash,
                                                   root_hash=file_object.root_hash,
                                                   source=self.scanner_name)
                    self.children.append(child_fo)

            except ValueError:
                file_object.flags.append(f"{self.scanner_name}::value_error")
