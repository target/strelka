import re

import olefile
import oletools

from strelka import strelka


class ScanOle(strelka.Scanner):
    """Extracts files from OLECF files."""

    def scan(self, data, file, options, expire_at):
        ole = None
        self.event["total"] = {"streams": 0, "extracted": 0}

        try:
            ole = olefile.OleFileIO(data)
            ole_streams = ole.listdir(streams=True)
            self.event["total"]["streams"] = len(ole_streams)
            for stream in ole_streams:
                try:
                    file = ole.openstream(stream)
                    extract_data = file.read()
                    extract_name = f'{"_".join(stream)}'
                    extract_name = re.sub(r"[\x00-\x1F]", "", extract_name)
                    if extract_name.endswith("Ole10Native"):
                        native_stream = oletools.oleobj.OleNativeStream(
                            bindata=extract_data,
                        )
                        if native_stream.filename:
                            extract_name = (
                                extract_name + f"_{str(native_stream.filename)}"
                            )
                        else:
                            extract_name = extract_name + "_native_data"

                        # Send extracted file back to Strelka
                        self.emit_file(native_stream.data, name=extract_name)

                    else:
                        # Send extracted file back to Strelka
                        self.emit_file(extract_data, name=extract_name)

                    self.event["total"]["extracted"] += 1
                except AttributeError:
                    self.flags.append("attribute_error_in_stream")

        except OSError:
            self.flags.append("os_error")
        finally:
            if ole:
                ole.close()
