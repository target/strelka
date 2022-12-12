import datetime
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_iso import ScanIso


def test_scan_iso(mocker):
    """
    This tests the ScanIso scanner.
    It attempts to validate several given ISO metadata values.

    Pass: Sample event matches output of ScanIso.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_iso_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 1, "extracted": 1},
        "files": [
            {"filename": "/lorem.txt", "size": 4015, "date_utc": "2022-12-11T18:44:49Z"}
        ],
        "hidden_dirs": [],
        "meta": {
            "date_created": "2022-12-11T18:42:00Z",
            "date_effective": None,
            "date_expiration": None,
            "date_modification": "2022-12-11T18:42:00Z",
            "volume_identifier": "NEW_VOLUME                      ",
        },
    }

    scanner = ScanIso(
        {"name": "ScanIso", "key": "scan_iso", "limits": {"scanner": 10}},
        "test_coordinate",
    )

    mocker.patch.object(ScanIso, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test.iso").read_bytes(),
        {"uid": "12345", "name": "somename"},
        {"scanner_timeout": 5},
        datetime.date.today(),
    )

    TestCase().assertDictEqual(test_scan_iso_event, scanner.event)
