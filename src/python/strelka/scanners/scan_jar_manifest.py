from strelka import strelka


class ScanJarManifest(strelka.Scanner):
    """Collects metadata from JAR manifest files."""
    def scan(self, data, file, options, expire_at):
        manifest = b'\n'.join(data.splitlines()).rstrip(b'\n')
        section_strings = manifest.split(b'\n')
        self.event.setdefault('manifest', [])
        for section in section_strings:
            split_section = section.replace(b'\n ', b'').split(b': ')
            if len(split_section) == 2:
                jar_entry = {
                    'header': split_section[0],
                    'value': split_section[1],
                }
                if jar_entry not in self.event['manifest']:
                    self.event['manifest'].append(jar_entry)
