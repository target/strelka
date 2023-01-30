from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_iso import ScanIso as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_iso(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 1, "extracted": 1},
        "files": [
            {"filename": "/lorem.txt", "size": 4015, "date_utc": "2022-12-11T18:44:49"}
        ],
        "hidden_dirs": [],
        "meta": {
            "date_created": "2022-12-11T18:42:00",
            "date_effective": None,
            "date_expiration": None,
            "date_modification": "2022-12-11T18:42:00",
            "volume_identifier": "NEW_VOLUME                      ",
        },
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.iso",
    )

    TestCase().assertDictEqual(test_scan_event, scanner_event)
