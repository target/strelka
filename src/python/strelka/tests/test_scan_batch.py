from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_batch import ScanBatch as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_batch(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "tokens": [
            "Token.Punctuation",
            "Token.Keyword",
            "Token.Text",
            "Token.Name.Variable",
            "Token.Literal.String.Double",
            "Token.Operator",
            "Token.Comment.Single",
            "Token.Name.Label",
        ],
        "comments": [
            "REM Simple batch script for calling avrdude with options for USBtinyISP",
            "REM (C) 2012, 2013 Michael Bemmerl",
            "REM License: WTFPL-2.0",
        ],
        "keywords": ["echo", "SETLOCAL", "SET", "IF", "NOT", "GOTO"],
        "labels": ["help", "exit"],
        "strings": ["avrdude", "\\\\bin\\\\avrdude.exe"],
        "text": [
            "off",
            "\\n",
            "\\n\\n",
            "-c",
            "usbtiny",
            "-P",
            "usb",
            "You",
            "probably",
            "want",
            "to",
            "add",
            "at",
            "least",
            "the",
            "part",
            "option",
            "-p",
            "[partno]",
            ".",
            "and",
            "some",
            "other",
            "AVRDUDE",
            "command",
            "line",
            "like",
            "-U",
            "flash:w:[file]",
        ],
        "variables": ["AVRDUDE", "%AVR32_HOME%", "%1", "%AVRDUDE%", "%*"],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.bat",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
