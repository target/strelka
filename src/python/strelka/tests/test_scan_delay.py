from unittest import TestCase, mock

from strelka.scanners.scan_delay import ScanDelay as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_delay(mocker):
    """
    Pass: Scanner throws a ScannerTimeout exception, and adds a timed_out flag.
    Failure: ScannerTimeout is not caught
    """

    test_scan_event = {"elapsed": mock.ANY, "flags": ["timed_out"]}

    scanner_event = run_test_scan(
        mocker=mocker, scan_class=ScanUnderTest, options={"scanner_timeout": 1}
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
