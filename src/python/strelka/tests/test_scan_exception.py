from unittest import TestCase, mock

from strelka.scanners.scan_exception import ScanException as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_exception(mocker):
    """
    Pass: Exception should be caught by scan_wrapper(), a flag set, traceback added.
    Failure: Unable to load file or sample event fails to match, meaning the exception was uncaught.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["uncaught_exception"],
        "exception": mock.ANY,
    }

    scanner_event = run_test_scan(mocker=mocker, scan_class=ScanUnderTest)

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
