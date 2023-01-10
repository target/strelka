from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_footer import ScanFooter as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_footer_txt(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "footer": b"itae. Et tortor consequat id porta nibh venenatis.",
        "backslash": "itae. Et tortor consequat id porta nibh venenatis.",
        "hex": b"697461652e20457420746f72746f7220636f6e73657175617420696420706f727461206e6962682076656e656e617469732e",
        "raw": b"itae. Et tortor consequat id porta nibh venenatis.",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.txt",
        options={"encodings": ["classic", "raw", "hex", "backslash"]},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_footer_exe(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "footer": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "backslash": "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00",
        "hex": b"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "raw": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.exe",
        options={"encodings": ["classic", "raw", "hex", "backslash"]},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
