import datetime
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_bzip2 import ScanBzip2


def test_scan_bzip2(mocker):
    """
    This tests the ScanBzip2 scanner with a BZIP2 file.

    Pass: Sample event matches output of Bzip2.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_bzip2_event = {
        "elapsed": mock.ANY,
        "flags": [],
        'size': 4015
    }

    scanner = ScanBzip2(
        {"name": "ScanBzip2", "key": "scan_bzip2", "limits": {"scanner": 10}},
        "test_coordinate",
    )

    mocker.patch.object(ScanBzip2, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test.bz2").read_bytes(),
        {"uid": "12345", "name": "somename"},
        {"scanner_timeout": 5},
        datetime.date.today(),
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_bzip2_event, scanner.event)
