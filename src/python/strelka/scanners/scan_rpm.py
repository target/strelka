import tempfile

import rpmfile

from strelka import strelka


class ScanRpm(strelka.Scanner):
    """Collects metadata and extracts files from RPM files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get("tmp_directory", "/tmp/")

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            try:
                with rpmfile.open(tmp_data.name) as rpm_obj:
                    extract_name = ""
                    for key, value in rpm_obj.headers.items():
                        if key == "arch":
                            self.event["architecture"] = value
                        elif key == "archive_compression":
                            self.event["archive_compression"] = value
                        elif key == "archive_format":
                            self.event["archive_format"] = value
                        elif key == "authors":
                            self.event["authors"] = value
                        elif key == "buildhost":
                            self.event["build_host"] = value
                        elif key == "buildtime":
                            self.event["build_time"] = value
                        elif key == "copyright":
                            self.event["copyright"] = value
                        elif key == "description":
                            if value is not None:
                                self.event["description"] = value.replace(b"\n", b" ")
                        elif key == "filenames":
                            self.event["filenames"] = value
                        elif key == "group":
                            self.event["group"] = value
                        elif key == "name":
                            self.event["name"] = value
                            extract_name = f"{value.decode()}"
                        elif key == "os":
                            self.event["os"] = value
                        elif key == "packager":
                            self.event["packager"] = value
                        elif key == "provides":
                            self.event["provides"] = value
                        elif key == "release":
                            self.event["release"] = value
                        elif key == "requirename":
                            self.event["require_name"] = value
                        elif key == "rpmversion":
                            self.event["rpm_version"] = value
                        elif key == "serial":
                            self.event["serial"] = value
                        elif key == "sourcerpm":
                            self.event["source_rpm"] = value
                        elif key == "summary":
                            self.event["summary"] = value
                        elif key == "vendor":
                            self.event["vendor"] = value
                        elif key == "version":
                            self.event["version"] = value
                        elif key == "url":
                            self.event["url"] = value

                    # Send extracted file back to Strelka
                    self.emit_file(
                        data[rpm_obj.data_offset :], name=extract_name
                    )  # FIXME: extract_name always empty string

            except ValueError:
                self.flags.append("value_error")
