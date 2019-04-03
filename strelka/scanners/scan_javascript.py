import esprima
import jsbeautifier

from strelka import core


class ScanJavascript(core.StrelkaScanner):
    """Collects metadata from JavaScript files.

    Options:
        beautify: Boolean that determines if JavaScript should be
            deobfuscated.
            Defaults to True.
    """
    def scan(self, st_file, options):
        beautify = options.get('beautify', True)

        self.metadata.setdefault('tokens', [])
        self.metadata.setdefault('keywords', [])
        self.metadata.setdefault('strings', [])
        self.metadata.setdefault('identifiers', [])
        self.metadata.setdefault('regularExpressions', [])
        self.metadata['beautified'] = False

        js = None

        try:
            if beautify:
                js = jsbeautifier.beautify(self.data.decode())
                self.metadata['beautified'] = True
        except:  # noqa
            self.flags.append('beautify_failed')

        if js is None:
            js = file_object.data.decode()

        tokens = esprima.tokenize(
            js,
            options={
                'comment': True,
                'tolerant': True,
            }
        )
        for t in tokens:
            if t.type not in self.metadata['tokens']:
                self.metadata['tokens'].append(t.type)
            if t.type == 'String':
                stripped_val = t.value.strip('"\'')
                if stripped_val not in self.metadata['strings']:
                    self.metadata['strings'].append(stripped_val)
            if t.type == 'Keyword':
                if t.value not in self.metadata['keywords']:
                    self.metadata['keywords'].append(t.value)
            if t.type == 'Identifier':
                if t.value not in self.metadata['identifiers']:
                    self.metadata['identifiers'].append(t.value)
            if type == 'RegularExpression':
                if t.value not in self.metadata['regularExpressions']:
                    self.metadata['regularExpressions'].append(t.value)
