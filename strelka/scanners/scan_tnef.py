import tnefparse

from strelka import core


class ScanTnef(core.StrelkaScanner):
    """Collects metadata and extract files from TNEF files."""
    def scan(self, data, file_object, options):
        self.metadata['total'] = {'attachments': 0, 'extracted': 0}

        tnef = tnefparse.TNEF(data)

        self.metadata.setdefault('objectNames', [])
        tnef_objects = getattr(tnef, 'objects', [])
        for object in tnef_objects:
            descriptive_name = tnefparse.TNEF.codes.get(object.name)
            if descriptive_name not in self.metadata['objectNames']:
                self.metadata['objectNames'].append(descriptive_name)

            object_data = object.data.strip(b'\0') or None
            if object_data is not None:
                if descriptive_name == 'Subject':
                    self.metadata['subject'] = object_data
                elif descriptive_name == 'Message ID':
                    self.metadata['messageId'] = object_data
                elif descriptive_name == 'Message Class':
                    self.metadata['messageClass'] = object_data

        tnef_attachments = getattr(tnef, 'attachments', [])
        self.metadata['total']['attachments'] = len(tnef_attachments)
        for attachment in tnef_attachments:
            file_ = core.StrelkaFile(
                name=f'{attachment.name.decode()}',
                source=self.scanner_name,
            )
            self.r0.setex(
                file_.uid,
                self.expire,
                attachment.data,
            )
            self.files.append(file_)
            self.metadata['total']['extracted'] += 1

        tnef_html = getattr(tnef, 'htmlbody', None)
        if tnef_html is not None:
            file_ = core.StrelkaFile(
                name='htmlbody',
                source=self.scanner_name,
            )
            self.r0.setex(
                file_.uid,
                self.expire,
                tnef_html.data,
            )
            self.files.append(file_)
