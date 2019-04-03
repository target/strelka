import tnefparse

from strelka import core
from strelka.scanners import util


class ScanTnef(core.StrelkaScanner):
    """Collects metadata and extract files from TNEF files."""
    def scan(self, st_file, options):
        self.metadata['total'] = {'attachments': 0, 'extracted': 0}

        tnef = tnefparse.TNEF(self.data)

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
            ex_file = core.StrelkaFile(
                name=f'{attachment.name.decode()}',
                source=self.name,
            )
            for c in util.chunk_string(attachment.data):
                p = self.fk.pipeline()
                p.rpush(ex_file.uid, c)
                p.expire(ex_file.uid, self.expire)
                p.execute()
            self.files.append(ex_file)

            self.metadata['total']['extracted'] += 1

        tnef_html = getattr(tnef, 'htmlbody', None)
        if tnef_html is not None:
            ex_file = core.StrelkaFile(
                name='htmlbody',
                source=self.name,
            )
            for c in util.chunk_string(tnef_html.data):
                p = self.fk.pipeline()
                p.rpush(ex_file.uid, c)
                p.expire(ex_file.uid, self.expire)
                p.execute()
            self.files.append(ex_file)
