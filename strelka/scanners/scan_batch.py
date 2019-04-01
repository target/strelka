import pygments
from pygments import formatters
from pygments import lexers

from strelka import core


class ScanBatch(core.StrelkaScanner):
    """Collects metadata from batch script files.

    Pygments is used as a lexer and the tokenized data is appended as metadata.

    Attributes:
        lexer: Pygments lexer ('batch') used to parse the file.
    """
    def init(self):
        self.lexer = lexers.get_lexer_by_name('batch')

    def scan(self, data, file_object, options):
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

        self.metadata.setdefault('tokens', [])
        self.metadata.setdefault('comments', [])
        self.metadata.setdefault('keywords', [])
        self.metadata.setdefault('labels', [])
        self.metadata.setdefault('strings', [])
        self.metadata.setdefault('text', [])
        self.metadata.setdefault('variables', [])

        position = 0
        while position < len(ordered_highlights):
            ohlp = ordered_highlights[position]
            if ohlp['token'] not in self.metadata['tokens']:
                self.metadata['tokens'].append(ohlp['token'])
            if ohlp['token'] == 'Token.Comment.Single':
                if ohlp['value'] not in self.metadata['comments']:
                    self.metadata['comments'].append(ohlp['value'])
            elif ohlp['token'] == 'Token.Keyword':
                if ohlp['value'] not in self.metadata['keywords']:
                    self.metadata['keywords'].append(ohlp['value'])
            elif ohlp['token'] == 'Token.Name.Label':
                if ohlp['value'] not in self.metadata['labels']:
                    self.metadata['labels'].append(ohlp['value'])
            elif ohlp['token'] == 'Token.Literal.String.Double':
                if ohlp['value'] not in self.metadata['strings']:
                    self.metadata['strings'].append(ohlp['value'])
            elif ohlp['token'] == 'Token.Literal.String.Single':
                if ohlp['value'] not in self.metadata['strings']:
                    self.metadata['strings'].append(ohlp['value'])
            elif ohlp['token'] == 'Token.Text':
                if ohlp['value'] not in self.metadata['text']:
                    self.metadata['text'].append(ohlp['value'])
            elif ohlp['token'] == 'Token.Name.Variable':
                if ohlp['value'] not in self.metadata['variables']:
                    self.metadata['variables'].append(ohlp['value'])
            position += 1
