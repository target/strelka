import datetime
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_rar import ScanRar as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_rar(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 3, "extracted": 3},
        "host_os": "RAR_OS_WIN32",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.rar",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
