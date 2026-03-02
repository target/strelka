from oletools import rtfobj

from strelka import strelka


class ScanRtf(strelka.Scanner):
    """Extracts files from RTF files.

    Options:
        limit: Maximum number of files to extract.
            Defaults to 1000.
    """

    def scan(self, data, file, options, expire_at):
        file_limit = options.get("limit", 1000)

        self.event["total"] = {"rtf_objects": 0, "extracted": 0}

        rtf = rtfobj.RtfObjParser(data)
        rtf.parse()
        self.event["total"]["rtf_objects"] = len(rtf.rtf_objects)

        # استخراج uuid من اسم الفايل بنفس الطريقة
        name = file.name or ""
        if "___" in name:
            uuid_part, _ = name.split("___", 1)
        else:
            uuid_part = "unknown/ScanRtf"

        for index, rtf_object in enumerate(rtf.rtf_objects):
            if self.event["total"]["extracted"] >= file_limit:
                break

            # تحديد البيانات اللي هتتبعت
            if rtf_object.is_package:
                file_bytes = rtf_object.olepkgdata
            elif rtf_object.is_ole:
                file_bytes = rtf_object.oledata
            else:
                file_bytes = rtf_object.rawdata

            # تسمية موحّدة بنفس نمط httpx
            emitted_name = f"{uuid_part}___file_{index}"

            self.emit_file(file_bytes, name=emitted_name)

            self.event["total"]["extracted"] += 1
