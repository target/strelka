import pygments
from pygments import formatters, lexers

from strelka import strelka


class ScanBatch(strelka.Scanner):
    """Collects metadata from batch script files.

    Pygments is used as a lexer and the tokenized data is appended as metadata.

    Attributes:
        lexer: Pygments lexer ('batch') used to parse the file.
    """

    def init(self):
        self.lexer = lexers.get_lexer_by_name("batch")

    def scan(self, data, file, options, expire_at):
        highlight = pygments.highlight(
            data,
            self.lexer,
            formatters.RawTokenFormatter(),
        )
        highlight_list = highlight.split(b"\n")

        ordered_highlights = []
        for hl in highlight_list:
            split_highlight = hl.split(b"\t")
            if len(split_highlight) == 2:
                token = split_highlight[0].decode()
                value = split_highlight[1].decode().strip("'\"").strip()
                highlight_entry = {"token": token, "value": value}
                if highlight_entry["value"]:
                    ordered_highlights.append(highlight_entry)

        self.event.setdefault("tokens", [])
        self.event.setdefault("comments", [])
        self.event.setdefault("keywords", [])
        self.event.setdefault("labels", [])
        self.event.setdefault("strings", [])
        self.event.setdefault("text", [])
        self.event.setdefault("variables", [])

        position = 0
        while position < len(ordered_highlights):
            ohlp = ordered_highlights[position]
            if ohlp["token"] not in self.event["tokens"]:
                self.event["tokens"].append(ohlp["token"])
            if ohlp["token"] == "Token.Comment.Single":
                if ohlp["value"] not in self.event["comments"]:
                    self.event["comments"].append(ohlp["value"])
            elif ohlp["token"] == "Token.Keyword":
                if ohlp["value"] not in self.event["keywords"]:
                    self.event["keywords"].append(ohlp["value"])
            elif ohlp["token"] == "Token.Name.Label":
                if ohlp["value"] not in self.event["labels"]:
                    self.event["labels"].append(ohlp["value"])
            elif ohlp["token"] == "Token.Literal.String.Double":
                if ohlp["value"] not in self.event["strings"]:
                    self.event["strings"].append(ohlp["value"])
            elif ohlp["token"] == "Token.Literal.String.Single":
                if ohlp["value"] not in self.event["strings"]:
                    self.event["strings"].append(ohlp["value"])
            elif ohlp["token"] == "Token.Text":
                if ohlp["value"] not in self.event["text"]:
                    self.event["text"].append(ohlp["value"])
            elif ohlp["token"] == "Token.Name.Variable":
                if ohlp["value"] not in self.event["variables"]:
                    self.event["variables"].append(ohlp["value"])
            position += 1
