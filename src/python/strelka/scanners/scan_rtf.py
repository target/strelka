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

        for rtf_object in rtf.rtf_objects:
            if self.event["total"]["extracted"] >= file_limit:
                break

            index = rtf.server.index(rtf_object)

            if rtf_object.is_package:
                # Send extracted file back to Strelka
                self.emit_file(rtf_object.olepkgdata, name=rtf_object.filename)

            elif rtf_object.is_ole:
                # Send extracted file back to Strelka
                self.emit_file(rtf_object.oledata, name=f"rtf_object_{index}")

            else:
                # Send extracted file back to Strelka
                self.emit_file(rtf_object.rawdata, name=f"rtf_object_{index}")

            self.event["total"]["extracted"] += 1
