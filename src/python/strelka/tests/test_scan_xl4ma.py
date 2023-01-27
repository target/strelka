from pathlib import Path
from unittest import TestCase, mock
from pytest_unordered import unordered

from strelka.scanners.scan_xl4ma import ScanXl4ma as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_xl4ma(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "decoded": unordered(['3', 'user', 'clean.xls', 'None', "https://www.example.com/path/to/resource"]),
        "iocs": ["https://www.example.com/path/to/resource"],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.xls",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
