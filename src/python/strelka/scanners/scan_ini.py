from strelka import strelka


class ScanIni(strelka.Scanner):
    """Parses keys from INI files."""
    def scan(self, data, file, options, expire_at):
        self.event['keys'] = []

        section = ''
        ini = data.splitlines()
        for key in ini:
            if key.startswith(b'[') and key.endswith(b']'):
                section = key[1:-1]
            else:
                split_key = key.split(b'=')
                if len(split_key) == 2:
                    self.event['keys'].append({
                        'section': section,
                        'name': split_key[0],
                        'value': split_key[1],
                    })
