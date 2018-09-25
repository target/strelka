import email

from server import objects


class ScanEmail(objects.StrelkaScanner):
    """Collects metadata and extract files from email messages."""
    def scan(self, file_object, options):
        self.metadata["total"] = {"parts": 0, "extracted": 0}
        message = email.message_from_string(file_object.data.decode("UTF-8", "replace"))

        self.metadata.setdefault("headers", [])
        for (key, value) in message.items():
            normalized_value = objects.normalize_whitespace(value.strip())
            header_entry = {"header": key, "value": normalized_value}
            if header_entry not in self.metadata["headers"]:
                self.metadata["headers"].append(header_entry)

        self.metadata.setdefault("parts", [])
        for (index, part) in enumerate(message.walk()):
            self.metadata["total"]["parts"] += 1
            child_file = part.get_payload(decode=True)
            if child_file is not None:
                part_filename = part.get_filename()
                if part_filename is not None:
                    child_filename = f"{self.scanner_name}::{part_filename}"
                    self.metadata["parts"].append(part_filename)
                else:
                    child_filename = f"{self.scanner_name}::part_{index}"

                child_fo = objects.StrelkaFile(data=child_file,
                                               filename=child_filename,
                                               depth=file_object.depth + 1,
                                               parent_uid=file_object.uid,
                                               root_uid=file_object.root_uid,
                                               parent_hash=file_object.hash,
                                               root_hash=file_object.root_hash,
                                               source=self.scanner_name,
                                               external_flavors=[part.get_content_type()])
                self.children.append(child_fo)
                self.metadata["total"]["extracted"] += 1
