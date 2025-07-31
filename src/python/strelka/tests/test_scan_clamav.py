from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_clamav import ScanClamav as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_clamav(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """
    test_scan_event = {
        "Data read": "0.51 MB (ratio 1.06",
        "Data scanned": "0.54 MB",
        "End Date": mock.ANY,
        "Engine version": mock.ANY,
        "Infected files": "0",
        "Known viruses": mock.ANY,
        "Scanned directories": "0",
        "Scanned files": "1",
        "Start Date": mock.ANY,
        "Time": mock.ANY,
        "elapsed": mock.ANY,
        "flags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.png",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
