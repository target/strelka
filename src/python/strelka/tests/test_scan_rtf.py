from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_rtf import ScanRtf as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_rtf(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"rtf_objects": 1, "extracted": 1},
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_object.rtf",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
