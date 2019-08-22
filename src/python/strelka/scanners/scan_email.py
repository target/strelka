import email

from strelka import strelka


class ScanEmail(strelka.Scanner):
    """Collects metadata and extract files from email messages."""
    def scan(self, data, file, options, expire_at):
        headers = options.get('headers', [])

        self.event['total'] = {'parts': 0, 'extracted': 0}

        try:
            message = email.message_from_string(
                data.decode('UTF-8', 'replace')
            )

            self.event['headers'] = []
            for h, v in message.items():
                if headers and h not in headers:
                    continue

                self.event['headers'].append({
                    'header': h,
                    'value': v,
                })

            self.event['parts'] = []
            for (index, part) in enumerate(message.walk()):
                self.event['total']['parts'] += 1
                extract_data = part.get_payload(decode=True)
                if extract_data is not None:
                    part_filename = part.get_filename()
                    if part_filename is not None:
                        extract_name = f'{part_filename}'
                        self.event['parts'].append(part_filename)
                    else:
                        extract_name = f'part_{index}'

                    extract_file = strelka.File(
                        name=extract_name,
                        source=self.name,
                    )
                    extract_file.add_flavors({'external': [part.get_content_type()]})

                    for c in strelka.chunk_string(extract_data):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                    self.files.append(extract_file)
                    self.event['total']['extracted'] += 1

        except AssertionError:
            self.flags.append('assertion_error')
