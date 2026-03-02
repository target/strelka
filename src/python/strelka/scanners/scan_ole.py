import re

import olefile
import oletools

from strelka import strelka


class ScanOle(strelka.Scanner):
    """Extracts files from OLECF files."""

    def scan(self, data, file, options, expire_at):
        ole = None
        self.event["total"] = {"streams": 0, "extracted": 0}

        # استخراج uuid_part من اسم الفايل الأصلي
        uuid_part = str(getattr(file, "name", "") or "")
        if "___" in uuid_part:
            uuid_part = uuid_part.split("___", 1)[0]
        else:
            uuid_part = "unknown/ScanOle"

        try:
            ole = olefile.OleFileIO(data)
            ole_streams = ole.listdir(streams=True)
            self.event["total"]["streams"] = len(ole_streams)

            for index, stream in enumerate(ole_streams):
                try:
                    ole_stream = ole.openstream(stream)
                    extract_data = ole_stream.read()

                    emitted_name = f"{uuid_part}___file_{index}"

                    if "_".join(stream).endswith("Ole10Native"):
                        native_stream = oletools.oleobj.OleNativeStream(
                            bindata=extract_data,
                        )

                        if native_stream.data:
                            self.emit_file(native_stream.data, name=emitted_name)
                    else:
                        self.emit_file(extract_data, name=emitted_name)

                    self.event["total"]["extracted"] += 1

                except AttributeError:
                    self.flags.append("attribute_error_in_stream")

        except OSError:
            self.flags.append("os_error")
        finally:
            if ole:
                ole.close()