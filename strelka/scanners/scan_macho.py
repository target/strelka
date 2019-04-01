import tempfile

import macholibre

from strelka import core


class ScanMacho(core.StrelkaScanner):
    """Collects metadata from Mach-O files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file_object, options):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        self.metadata['total'] = {'objects': 0}
        self.metadata.setdefault('abnormalities', [])
        self.metadata.setdefault('objects', [])

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as f:
            f.write(data)
            f.flush()

            macho_dictionary = macholibre.parse(f.name)
            for (key, value) in macho_dictionary.items():
                if key == 'abnormalities' and value not in self.metadata['abnormalities']:
                    self.metadata['abnormalities'].append(value)
                elif key == 'macho':
                    self.metadata['total']['objects'] = 1
                    self._macho_parse(self, value)
                elif key == 'universal':
                    for (x, y) in value.items():
                        if key == 'machos':
                            self.metadata['total']['objects'] = len(y)
                            for macho in y:
                                self._macho_parse(self, macho)

    @staticmethod
    def _macho_parse(self, macho_dictionary):
        """Parses macholibre dictionary."""
        macho_out = {}
        import_cache = {}

        for (key, value) in macho_dictionary.items():
            if key == 'strtab':
                macho_out['strTab'] = value
            elif key == 'filetype':
                macho_out['fileType'] = value
            elif key == 'cputype':
                macho_out['cpuType'] = value
            elif key == 'subtype':
                macho_out['subType'] = value
            elif key == 'slcs':
                macho_out['slcs'] = value
            elif key == 'nlcs':
                macho_out['ncls'] = value
            elif key == 'dylibs':
                macho_out['dylibs'] = value
            elif key == 'flags':
                macho_out['flags'] = value
            elif key == 'minos':
                macho_out['minOs'] = value
            elif key == 'imports':
                macho_out.setdefault('imports', [])
                for (function, import_) in value:
                    if import_ not in import_cache:
                        macho_out['imports'].append(import_)
                        import_cache.setdefault(import_, [])
                    import_cache[import_].append(function)

        macho_out.setdefault('importFunctions', [])
        for (import_, function,) in import_cache.items():
            import_entry = {'import': import_, 'functions': function}
            if import_entry not in macho_out['importFunctions']:
                macho_out['importFunctions'].append(import_entry)

        self.metadata['objects'].append(macho_out)
