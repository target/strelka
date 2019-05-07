import pygments
from pygments import formatters
from pygments import lexers

from strelka import strelka


class ScanVb(strelka.Scanner):
    """Collects metadata from Visual Basic script files.

    Attributes:
        lexer: Pygments lexer ('vbnet') used to parse the file.
    """
    def init(self):
        self.lexer = lexers.get_lexer_by_name('vbnet')

    def scan(self, data, file, options, expire_at):
        highlight = pygments.highlight(
            data,
            self.lexer,
            formatters.RawTokenFormatter(),
        )
        highlight_list = highlight.split(b'\n')

        ordered_highlights = []
        for hl in highlight_list:
            split_highlight = hl.split(b'\t')
            if len(split_highlight) == 2:
                token = split_highlight[0].decode()
                value = split_highlight[1].decode().strip('\'"').strip()
                highlight_entry = {'token': token, 'value': value}
                if highlight_entry['value']:
                    ordered_highlights.append(highlight_entry)

        self.event.setdefault('tokens', [])
        self.event.setdefault('comments', [])
        self.event.setdefault('functions', [])
        self.event.setdefault('names', [])
        self.event.setdefault('operators', [])
        self.event.setdefault('strings', [])

        position = 0
        while position < len(ordered_highlights):
            ohlp = ordered_highlights[position]
            if ohlp['token'] not in self.event['tokens']:
                self.event['tokens'].append(ohlp['token'])
            if ohlp['token'] == 'Token.Comment':
                if ohlp['value'] not in self.event['comments']:
                    self.event['comments'].append(ohlp['value'])
            elif ohlp['token'] == 'Token.Name.Function':
                if ohlp['value'] not in self.event['functions']:
                    self.event['functions'].append(ohlp['value'])
            elif ohlp['token'] == 'Token.Name':
                if ohlp['value'] not in self.event['names']:
                    self.event['names'].append(ohlp['value'])
            elif ohlp['token'] == 'Token.Operator':
                if ohlp['value'] not in self.event['operators']:
                    self.event['operators'].append(ohlp['value'])
            elif ohlp['token'] == 'Token.Literal.String':
                if ohlp['value'] not in self.event['strings']:
                    self.event['strings'].append(ohlp['value'])
            position += 1
