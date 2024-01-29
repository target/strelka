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
                "LineComment",
                "String",
                "Identifier",
                "Punctuator",
                "RegularExpression",
                "Numeric",
                "BlockComment",
                "Keyword",
            ]
        ),
        "keywords": unordered(
            [
                "var",
                "in",
                "this",
                "typeof",
                "return",
                "function",
                "if",
                "else",
                "throw",
                "new",
                "for",
            ]
        ),
        "strings": unordered(
            [
                "",
                "ws",
                "open",
                "string",
                "ftp://suspicious-ftp-server.org",
                "Checking URL: ",
                "Fetching data from: ",
                "base64",
                "path",
                ".",
                "-",
                " (",
                "fs",
                "utf8",
                "package.json",
                "https://another-example-bad-site.net",
                "Found unknown type of partial ",
                "use strict",
                ") in Handlebars partial Array => ",
                "function",
                "Could not find partial with name ",
                "http://example-malicious-site.com",
                "http://example-malicious-site.com/data",
                "Connection established",
            ]
        ),
        "identifiers": unordered(
            [
                "compile",
                "Handlebars",
                "send",
                "urls",
                "partials",
                "JSON",
                "pkg",
                "open",
                "eval",
                "console",
                "params",
                "cwd",
                "register",
                "key",
                "replace",
                "suspiciousUrl",
                "toLowerCase",
                "hasOwnProperty",
                "WebSocket",
                "concat",
                "arguments",
                "ws",
                "partial",
                "Buffer",
                "helpers",
                "btoa",
                "dynamicEval",
                "opt",
                "slugify",
                "str",
                "jsonStringify",
                "process",
                "url",
                "stringify",
                "i",
                "fetchDataFromUrl",
                "context",
                "log",
                "SafeString",
                "on",
                "checkMultipleUrls",
                "code",
                "helper",
                "escape",
                "a",
                "Utils",
                "name",
                "atob",
                "fs",
                "obj",
                "join",
                "path",
                "module",
                "forEach",
                "length",
                "establishWebSocket",
                "arr",
                "b",
                "require",
                "readFileSync",
                "toString",
                "parse",
                "exports",
                "escapeExpression",
                "registerHelper",
            ]
        ),
        "regular_expressions": unordered(["/ +/g", "/[^\\w ]+/g"]),
        "suspicious_keywords": unordered(["WebSocket", "eval"]),
        "urls": unordered(
            [
                "https://another-example-bad-site.net",
                "http://example-malicious-site.com",
                "ftp://suspicious-ftp-server.org",
                "http://example-malicious-site.com/data",
            ]
        ),
        "beautified": True,
        "script_length_bytes": 3127,
        "iocs": unordered(
            [
                {
                    "ioc": "suspicious-ftp-server.org",
                    "ioc_type": "domain",
                    "scanner": "ScanJavascript",
                },
                {
                    "ioc": "ftp://suspicious-ftp-server.org",
                    "ioc_type": "url",
                    "scanner": "ScanJavascript",
                },
                {
                    "ioc": "example-malicious-site.com",
                    "ioc_type": "domain",
                    "scanner": "ScanJavascript",
                },
                {
                    "ioc": "http://example-malicious-site.com",
                    "ioc_type": "url",
                    "scanner": "ScanJavascript",
                },
                {
                    "ioc": "http://example-malicious-site.com/data",
                    "ioc_type": "url",
                    "scanner": "ScanJavascript",
                },
                {
                    "ioc": "another-example-bad-site.net",
                    "ioc_type": "domain",
                    "scanner": "ScanJavascript",
                },
                {
                    "ioc": "https://another-example-bad-site.net",
                    "ioc_type": "url",
                    "scanner": "ScanJavascript",
                },
            ]
        ),
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.js",
        options=({"max_strings": 500}),
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_javascript_character_max_strings(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "tokens": unordered(["Punctuator", "BlockComment"]),
        "keywords": unordered(["return", "this"]),
        "strings": unordered(["", "Checking URL: "]),
        "identifiers": unordered(["arguments", "process"]),
        "regular_expressions": unordered(["/ +/g", "/[^\\w ]+/g"]),
        "suspicious_keywords": unordered(["WebSocket", "eval"]),
        "urls": unordered(
            [
                "http://example-malicious-site.com/data",
                "https://another-example-bad-site.net",
            ]
        ),
        "beautified": True,
        "script_length_bytes": 3127,
        "iocs": unordered(
            [
                {
                    "ioc": "example-malicious-site.com",
                    "ioc_type": "domain",
                    "scanner": "ScanJavascript",
                },
                {
                    "ioc": "http://example-malicious-site.com/data",
                    "ioc_type": "url",
                    "scanner": "ScanJavascript",
                },
                {
                    "ioc": "another-example-bad-site.net",
                    "ioc_type": "domain",
                    "scanner": "ScanJavascript",
                },
                {
                    "ioc": "https://another-example-bad-site.net",
                    "ioc_type": "url",
                    "scanner": "ScanJavascript",
                },
            ]
        ),
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.js",
        options={"max_strings": 2},
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
