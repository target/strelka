import datetime
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_rar import ScanRar


def test_scan_rar(mocker):
    """
    This tests the ScanRar scanner with a RAR file.

    Pass: Sample event matches output of ScanRar.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_rar_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 3, "extracted": 3},
        "host_os": "RAR_OS_WIN32",
    }

    scanner = ScanRar(
        {"name": "ScanRar", "key": "scan_rar", "limits": {"scanner": 10}},
        "test_coordinate",
    )

    mocker.patch.object(ScanRar, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test.rar").read_bytes(),
        {"uid": "12345", "name": "somename"},
        {"scanner_timeout": 5},
        datetime.date.today(),
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_rar_event, scanner.event)
