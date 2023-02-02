import tnefparse

from strelka import strelka


class ScanTnef(strelka.Scanner):
    """Collects metadata and extract files from TNEF files."""

    def scan(self, data, file, options, expire_at):
        self.event["total"] = {"attachments": 0, "extracted": 0}
        self.event.setdefault("object_names", [])

        tnef = tnefparse.TNEF(data)
        tnef_objects = getattr(tnef, "objects", [])
        for tnef_object in tnef_objects:
            descriptive_name = tnefparse.TNEF.codes.get(tnef_object.name)
            if descriptive_name not in self.event["object_names"]:
                self.event["object_names"].append(descriptive_name)

            try:
                object_data = tnef_object.data.strip(b"\0") or None
            except strelka.ScannerTimeout:
                raise
            except Exception:
                object_data = tnef_object.data

            if object_data is not None:
                if descriptive_name == "Subject":
                    self.event["subject"] = object_data
                elif descriptive_name == "Message ID":
                    self.event["message_id"] = object_data
                elif descriptive_name == "Message Class":
                    self.event["message_class"] = object_data

        tnef_attachments = getattr(tnef, "attachments", [])
        self.event["total"]["attachments"] = len(tnef_attachments)
        for attachment in tnef_attachments:
            # Send extracted file back to Strelka
            self.emit_file(attachment.data, name=attachment.name.decode())

            self.event["total"]["extracted"] += 1

        tnef_html = getattr(tnef, "htmlbody", None)
        if tnef_html:
            # Send extracted file back to Strelka
            self.emit_file(tnef_html, name="htmlbody")
