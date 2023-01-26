from pathlib import Path
from unittest import TestCase, mock

from pytest_unordered import unordered
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
        "tokens": unordered(
            [
                "BlockComment",
                "String",
                "Punctuator",
                "Keyword",
                "Identifier",
                "LineComment",
                "RegularExpression",
                "Numeric",
            ]
        ),
        "keywords": unordered(
            [
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
            ]
        ),
        "strings": unordered(
            [
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
            ]
        ),
        "identifiers": unordered(
            [
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
            ]
        ),
        "regular_expressions": unordered(["/[^\\w ]+/g", "/ +/g"]),
        "beautified": True,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.js",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_javascript_character_limits(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "tokens": unordered(
            [
                "BlockComment",
                "String",
                "Punctuator",
                "Keyword",
            ]
        ),
        "keywords": unordered(["throw", "return", "else", "var", "new"]),
        "strings": unordered(["", "path", "string", "-", "base64"]),
        "identifiers": unordered(["exports", "params", "cwd", "Buffer", "escape"]),
        "regular_expressions": unordered(["/[^\\w ]+/g", "/ +/g"]),
        "beautified": True,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.js",
        options={"limits": 5},
    )

    TestCase.maxDiff = None
    TestCase().assertLessEqual(
        len(test_scan_event["keywords"]), len(scanner_event["keywords"])
    )
    TestCase().assertLessEqual(
        len(test_scan_event["regular_expressions"]),
        len(scanner_event["regular_expressions"]),
    )
    TestCase().assertLessEqual(
        len(test_scan_event["identifiers"]), len(scanner_event["identifiers"])
    )
    TestCase().assertLessEqual(
        len(test_scan_event["strings"]), len(scanner_event["strings"])
    )
    TestCase().assertLessEqual(
        len(test_scan_event["tokens"]), len(scanner_event["tokens"])
    )
