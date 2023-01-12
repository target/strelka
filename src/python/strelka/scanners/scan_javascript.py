import esprima
import jsbeautifier

from strelka import strelka


class ScanJavascript(strelka.Scanner):
    """Collects metadata from JavaScript files.

    Options:
        beautify: Boolean that determines if JavaScript should be
            deobfuscated.
            Defaults to True.
    """
    def scan(self, data, file, options, expire_at):
        beautify = options.get('beautify', True)

        self.event.setdefault('tokens', [])
        self.event.setdefault('keywords', [])
        self.event.setdefault('strings', [])
        self.event.setdefault('identifiers', [])
        self.event.setdefault('regular_expressions', [])
        self.event['beautified'] = False

        js = None

        try:
            if beautify:
                js = jsbeautifier.beautify(data.decode())
                self.event['beautified'] = True
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append('beautify_failed')

        if js is None:
            js = data.decode()

        tokens = esprima.tokenize(
            js,
            options={
                'comment': True,
                'tolerant': True,
            }
        )
        for t in tokens:
            if t.type not in self.event['tokens']:
                self.event['tokens'].append(t.type)
            if t.type == 'String':
                stripped_val = t.value.strip('"\'')
                if stripped_val not in self.event['strings']:
                    self.event['strings'].append(stripped_val)
            if t.type == 'Keyword':
                if t.value not in self.event['keywords']:
                    self.event['keywords'].append(t.value)
            if t.type == 'Identifier':
                if t.value not in self.event['identifiers']:
                    self.event['identifiers'].append(t.value)
            if t.type == 'RegularExpression':
                if t.value not in self.event['regular_expressions']:
                    self.event['regular_expressions'].append(t.value)
