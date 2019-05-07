import tempfile

import macholibre

from strelka import strelka


class ScanMacho(strelka.Scanner):
    """Collects metadata from Mach-O files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        self.event['total'] = {'objects': 0}
        self.event.setdefault('abnormalities', [])
        self.event.setdefault('objects', [])

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as st_tmp:
            st_tmp.write(data)
            st_tmp.flush()

            macho_dictionary = macholibre.parse(st_tmp.name)
            for (key, value) in macho_dictionary.items():
                if key == 'abnormalities' and value not in self.event['abnormalities']:
                    self.event['abnormalities'].append(value)
                elif key == 'macho':
                    self.event['total']['objects'] = 1
                    self._macho_parse(self, value)
                elif key == 'universal':
                    for (x, y) in value.items():
                        if key == 'machos':
                            self.event['total']['objects'] = len(y)
                            for macho in y:
                                self._macho_parse(self, macho)

    @staticmethod
    def _macho_parse(self, macho_dictionary):
        """Parses macholibre dictionary."""
        macho_out = {}
        import_cache = {}

        for (key, value) in macho_dictionary.items():
            if key == 'strtab':
                macho_out['str_tab'] = value
            elif key == 'filetype':
                macho_out['file_type'] = value
            elif key == 'cputype':
                macho_out['cpu_type'] = value
            elif key == 'subtype':
                macho_out['sub_type'] = value
            elif key == 'slcs':
                macho_out['slcs'] = value
            elif key == 'nlcs':
                macho_out['ncls'] = value
            elif key == 'dylibs':
                macho_out['dylibs'] = value
            elif key == 'flags':
                macho_out['flags'] = value
            elif key == 'minos':
                macho_out['min_os'] = value
            elif key == 'imports':
                macho_out.setdefault('imports', [])
                for (function, import_) in value:
                    if import_ not in import_cache:
                        macho_out['imports'].append(import_)
                        import_cache.setdefault(import_, [])
                    import_cache[import_].append(function)

        macho_out.setdefault('import_functions', [])
        for (import_, function,) in import_cache.items():
            import_entry = {'import': import_, 'functions': function}
            if import_entry not in macho_out['import_functions']:
                macho_out['import_functions'].append(import_entry)

        self.event['objects'].append(macho_out)
