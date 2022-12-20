from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_javascript import ScanJavascript as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_javascript(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "tokens": [
            "BlockComment",
            "String",
            "Punctuator",
            "Keyword",
            "Identifier",
            "LineComment",
            "RegularExpression",
            "Numeric",
        ],
        "keywords": [
            "var",
            "function",
            "return",
            "for",
            "if",
            "throw",
            "else",
            "typeof",
            "new",
            "this",
            "in",
        ],
        "strings": [
            "use strict",
            "path",
            "fs",
            "package.json",
            "",
            "-",
            "Could not find partial with name ",
            ".",
            "string",
            "function",
            "Found unknown type of partial ",
            " (",
            ") in Handlebars partial Array => ",
            "base64",
            "utf8",
        ],
        "identifiers": [
            "path",
            "require",
            "fs",
            "module",
            "exports",
            "register",
            "Handlebars",
            "opt",
            "params",
            "pkg",
            "JSON",
            "parse",
            "readFileSync",
            "join",
            "process",
            "cwd",
            "slugify",
            "str",
            "toLowerCase",
            "replace",
            "helpers",
            "key",
            "escape",
            "Utils",
            "escapeExpression",
            "jsonStringify",
            "obj",
            "stringify",
            "concat",
            "arr",
            "i",
            "arguments",
            "length",
            "partial",
            "name",
            "context",
            "partials",
            "compile",
            "SafeString",
            "atob",
            "a",
            "Buffer",
            "toString",
            "btoa",
            "b",
            "helper",
            "hasOwnProperty",
            "registerHelper",
        ],
        "regular_expressions": ["/[^\\w ]+/g", "/ +/g"],
        "beautified": True,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.js",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
