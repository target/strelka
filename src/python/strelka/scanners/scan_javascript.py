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
        max_strings = options.get("max_strings", 50)

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
            self.flags.append(
                f"{self.__class__.__name__} Exception:  Javascript beautification failed."
            )

        try:
            if js is None:
                js = data.decode()
        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append(
                f"{self.__class__.__name__} Exception:  Javascript decoding failure."
            )

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

        except strelka.ScannerTimeout:
            raise
        except Exception:
            self.flags.append(
                f"{self.__class__.__name__} Exception:  Javascript tokenization failed."
            )

        try:
            self.event["tokens"] = list(self.event["tokens"])[:max_strings]
            self.event["keywords"] = list(self.event["keywords"])[:max_strings]
            self.event["strings"] = list(self.event["strings"])[:max_strings]
            self.event["identifiers"] = list(self.event["identifiers"])[:max_strings]
            self.event["regular_expressions"] = list(self.event["regular_expressions"])[
                :max_strings
            ]
        except Exception:
            self.flags.append(
                f"{self.__class__.__name__} Exception:  Error converting event data from set to list."
            )
