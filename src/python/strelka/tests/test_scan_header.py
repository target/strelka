from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_header import ScanHeader as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_header(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "header": b"Lorem ipsum dolor sit amet, consectetur adipiscing",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.txt",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
