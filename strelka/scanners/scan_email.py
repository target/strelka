import email

from strelka import core
from strelka.scanners import util


class ScanEmail(core.StrelkaScanner):
    """Collects metadata and extract files from email messages."""
    def scan(self, data, file_object, options):
        self.metadata['total'] = {'parts': 0, 'extracted': 0}

        try:
            message = email.message_from_string(
                data.decode('UTF-8', 'replace')
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
                file_data = part.get_payload(decode=True)
                if file_data is not None:
                    part_filename = part.get_filename()
                    if part_filename is not None:
                        file_name = f'{part_filename}'
                        self.metadata['parts'].append(part_filename)
                    else:
                        file_name = f'part_{index}'

                    file_ = core.StrelkaFile(
                        name=file_name,
                        source=self.scanner_name,
                    )
                    file_.add_flavors({'external': [part.get_content_type()]})
                    self.r0.setex(
                        file_.uid,
                        self.expire,
                        file_data,
                    )
                    self.files.append(file_)
                    self.metadata['total']['extracted'] += 1

        except AssertionError:
            self.flags.add(f'{self.scanner_name}::assertion_error')
