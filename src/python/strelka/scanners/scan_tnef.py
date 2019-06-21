import tnefparse

from strelka import strelka


class ScanTnef(strelka.Scanner):
    """Collects metadata and extract files from TNEF files."""
    def scan(self, data, file, options, expire_at):
        self.event['total'] = {'attachments': 0, 'extracted': 0}
        self.event.setdefault('object_names', [])

        tnef = tnefparse.TNEF(data)
        tnef_objects = getattr(tnef, 'objects', [])
        for tnef_object in tnef_objects:
            descriptive_name = tnefparse.TNEF.codes.get(tnef_object.name)
            if descriptive_name not in self.event['object_names']:
                self.event['object_names'].append(descriptive_name)

            object_data = tnef_object.data.strip(b'\0') or None
            if object_data is not None:
                if descriptive_name == 'Subject':
                    self.event['subject'] = object_data
                elif descriptive_name == 'Message ID':
                    self.event['message_id'] = object_data
                elif descriptive_name == 'Message Class':
                    self.event['message_class'] = object_data

        tnef_attachments = getattr(tnef, 'attachments', [])
        self.event['total']['attachments'] = len(tnef_attachments)
        for attachment in tnef_attachments:
            extract_file = strelka.File(
                name=attachment.name.decode(),
                source=self.name,
            )

            for c in strelka.chunk_string(attachment.data):
                self.upload_to_coordinator(
                    extract_file.pointer,
                    c,
                    expire_at,
                )

            self.files.append(extract_file)
            self.event['total']['extracted'] += 1

        tnef_html = getattr(tnef, 'htmlbody', None)
        if tnef_html is not None:
            extract_file = strelka.File(
                name='htmlbody',
                source=self.name,
            )

            for c in strelka.chunk_string(tnef_html.data):
                self.upload_to_coordinator(
                    extract_file.pointer,
                    c,
                    expire_at,
                )

            self.files.append(extract_file)
