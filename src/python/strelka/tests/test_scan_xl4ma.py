from pathlib import Path
from unittest import TestCase, mock

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
        "decoded": ["https://www.fake-website.com/path/to/resource?param1=value1&param2=value2#some-fragment"],
        "iocs": ["https://www.fake-website.com/path/to/resource"],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.xlsm",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
