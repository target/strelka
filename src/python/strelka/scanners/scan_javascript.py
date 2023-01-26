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
        beautify = options.get("beautify", True)
        limits = options.get("limits", 50)

        self.event.setdefault("tokens", set())
        self.event.setdefault("keywords", set())
        self.event.setdefault("strings", set())
        self.event.setdefault("identifiers", set())
        self.event.setdefault("regular_expressions", set())
        self.event["beautified"] = False

        js = None

        try:
            if beautify:
                js = jsbeautifier.beautify(data.decode())
                self.event["beautified"] = True
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("beautify_failed")

        try:
            if js is None:
                js = data.decode()
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("decode_failed")

        try:
            tokens = esprima.tokenize(
                js,
                options={
                    "comment": True,
                    "tolerant": True,
                },
            )
            for t in tokens:
                if t.type not in self.event["tokens"]:
                    self.event["tokens"].add(t.type)
                if t.type == "String":
                    stripped_val = t.value.strip("\"'")
                    if stripped_val not in self.event["strings"]:
                        self.event["strings"].add(stripped_val)
                if t.type == "Keyword":
                    if t.value not in self.event["keywords"]:
                        self.event["keywords"].add(t.value)
                if t.type == "Identifier":
                    if t.value not in self.event["identifiers"]:
                        self.event["identifiers"].add(t.value)
                if t.type == "RegularExpression":
                    if t.value not in self.event["regular_expressions"]:
                        self.event["regular_expressions"].add(t.value)

            self.event["tokens"] = list(self.event["tokens"])[:limits]
            self.event["keywords"] = list(self.event["keywords"])[:limits]
            self.event["strings"] = list(self.event["strings"])[:limits]
            self.event["identifiers"] = list(self.event["identifiers"])[:limits]
            self.event["regular_expressions"] = list(self.event["regular_expressions"])[
                :limits
            ]
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append("tokenization_failed")
