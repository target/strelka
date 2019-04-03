import email

from strelka import core
from strelka.scanners import util


class ScanEmail(core.StrelkaScanner):
    """Collects metadata and extract files from email messages."""
    def scan(self, st_file, options):
        self.metadata['total'] = {'parts': 0, 'extracted': 0}

        try:
            message = email.message_from_string(
                self.data.decode('UTF-8', 'replace')
            )

            self.metadata.setdefault('headers', [])
            for (key, value) in message.items():
                normalized_value = util.normalize_whitespace(value.strip())
                header_entry = {'header': key, 'value': normalized_value}
                if header_entry not in self.metadata['headers']:
                    self.metadata['headers'].append(header_entry)

            self.metadata.setdefault('parts', [])
            for (index, part) in enumerate(message.walk()):
                self.metadata['total']['parts'] += 1
                ex_data = part.get_payload(decode=True)
                if ex_data is not None:
                    part_filename = part.get_filename()
                    if part_filename is not None:
                        ex_name = f'{part_filename}'
                        self.metadata['parts'].append(part_filename)
                    else:
                        ex_name = f'part_{index}'

                    ex_file = core.StrelkaFile(
                        name=ex_name,
                        source=self.name,
                    )
                    ex_file.add_flavors({'external': [part.get_content_type()]})
                    for c in util.chunk_string(ex_data):
                        p = self.fk.pipeline()
                        p.rpush(ex_file.uid, c)
                        p.expire(ex_file.uid, self.expire)
                        p.execute()
                    self.files.append(ex_file)

                    self.metadata['total']['extracted'] += 1

        except AssertionError:
            self.flags.add('assertion_error')
