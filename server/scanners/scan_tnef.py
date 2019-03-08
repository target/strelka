import tnefparse

from server import lib


class ScanTnef(lib.StrelkaScanner):
    """Collects metadata and extract files from TNEF files."""
    def scan(self, file_object, options):
        self.metadata['total'] = {'attachments': 0, 'extracted': 0}

        tnef = tnefparse.TNEF(file_object.data)

        self.metadata.setdefault('objectNames', [])
        tnef_objects = getattr(tnef, 'objects', None)
        if tnef_objects is not None:
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

        tnef_attachments = getattr(tnef, 'attachments', None)
        if tnef_attachments is not None:
            self.metadata['total']['attachments'] = len(tnef_attachments)
            for attachment in tnef_attachments:
                child_filename = f'{self.scanner_name}::{attachment.name.decode()}'
                child_fo = lib.StrelkaFile(data=attachment.data,
                                           filename=child_filename,
                                           depth=file_object.depth + 1,
                                           parent_uid=file_object.uid,
                                           root_uid=file_object.root_uid,
                                           parent_hash=file_object.hash,
                                           root_hash=file_object.root_hash,
                                           source=self.scanner_name)
                self.children.append(child_fo)
                self.metadata['total']['extracted'] += 1

        tnef_html = getattr(tnef, 'htmlbody', None)
        if tnef_html is not None:
            child_fo = lib.StrelkaFile(data=tnef_html.data,
                                       filename=f'{self.scanner_name}::htmlbody',
                                       depth=file_object.depth + 1,
                                       parent_uid=file_object.uid,
                                       root_uid=file_object.root_uid,
                                       parent_hash=file_object.hash,
                                       root_hash=file_object.root_hash,
                                       source=self.scanner_name)
            self.children.append(child_fo)
