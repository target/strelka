from strelka import core


class ScanJarManifest(core.StrelkaScanner):
    """Collects metadata from JAR manifest files."""
    def scan(self, data, file_object, options):
        manifest = b'\n'.join(data.splitlines()).rstrip(b'\n')
        section_strings = manifest.split(b'\n')
        self.metadata.setdefault('manifest', [])
        for section in section_strings:
            split_section = section.replace(b'\n ', b'').split(b': ')
            if len(split_section) == 2:
                jar_entry = {
                    'header': split_section[0],
                    'value': split_section[1],
                }
                if jar_entry not in self.metadata['manifest']:
                    self.metadata['manifest'].append(jar_entry)
