from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_dmg import ScanDmg as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_dmg(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 5, "extracted": 5},
        "files": [
            {
                "filename": "Install/Install Flash Player/.background.png",
                "size": "70758",
                "datetime": "2022-12-28 16:28:45",
            },
            {
                "filename": "Install/Install Flash Player/.DS_Store",
                "size": "16388",
                "datetime": "2022-12-28 16:28:49",
            },
            {
                "filename": "Install/Install Flash Player/.VolumeIcon.icns",
                "size": "312349",
                "datetime": "2022-12-28 16:28:45",
            },
            {
                "filename": "Install/Install Flash Player/Install Flash Player",
                "size": "33016",
                "datetime": "2022-12-28 20:31:11",
            },
            {
                "filename": "Install/Install Flash Player/Install Flash Player_rsrc",
                "size": "51737",
                "datetime": "2022-12-28 16:28:45",
            },
        ],
        "hidden_dirs": [],
        "meta": {
            "7zip_version": "21.07",
            "partitions": [
                {
                    "path": mock.ANY,
                    "type": "HFS",
                    "created": "2022-12-28 20:18:31",
                }
            ],
        },
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.dmg",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
