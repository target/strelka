import email

from strelka import strelka


class ScanEmail(strelka.Scanner):
    """Collects metadata and extract files from email messages."""
    def scan(self, data, file, options, expire_at):
        self.metadata['total'] = {'parts': 0, 'extracted': 0}

        try:
            message = email.message_from_string(
                data.decode('UTF-8', 'replace')
            )

            self.metadata.setdefault('headers', [])
            for (key, value) in message.items():
                normalized_value = strelka.normalize_whitespace(value.strip())
                header_entry = {'header': key, 'value': normalized_value}
                if header_entry not in self.metadata['headers']:
                    self.metadata['headers'].append(header_entry)

            self.metadata.setdefault('parts', [])
            for (index, part) in enumerate(message.walk()):
                self.metadata['total']['parts'] += 1
                extract_data = part.get_payload(decode=True)
                if extract_data is not None:
                    part_filename = part.get_filename()
                    if part_filename is not None:
                        extract_name = f'{part_filename}'
                        self.metadata['parts'].append(part_filename)
                    else:
                        extract_name = f'part_{index}'

                    extract_file = strelka.File(
                        name=extract_name,
                        source=self.name,
                    )
                    extract_file.add_flavors({'external': [part.get_content_type()]})

                    for c in strelka.chunk_string(extract_data):
                        self.upload_to_cache(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                    self.files.append(extract_file)
                    self.metadata['total']['extracted'] += 1

        except AssertionError:
            self.flags.append('assertion_error')
