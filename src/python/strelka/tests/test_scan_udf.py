from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_udf import ScanUdf as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_udf(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 1, "extracted": 1},
        "files": [
            {
                "filename": "lorem.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
        ],
        "hidden_dirs": [],
        "meta": {
            "7zip_version": "24.09",
            "partitions": [
                {
                    "path": mock.ANY,
                    "type": "Udf",
                    "created": mock.ANY,
                },
            ],
        },
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_udf_1.50.img",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
