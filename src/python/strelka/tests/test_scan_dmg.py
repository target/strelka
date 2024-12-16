from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_dmg import ScanDmg as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_dmg_compressed(mocker):
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
                "datetime": mock.ANY,
            },
            {
                "filename": "Install/Install Flash Player/.DS_Store",
                "size": "16388",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install/Install Flash Player/.VolumeIcon.icns",
                "size": "312349",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install/Install Flash Player/Install Flash Player",
                "size": "33016",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install/Install Flash Player/Install Flash Player_rsrc",
                "size": "51737",
                "datetime": mock.ANY,
            },
        ],
        "meta": {
            "7zip_version": "24.09",
            "partitions": [
                {
                    "path": mock.ANY,
                    "type": "HFS",
                    "created": mock.ANY,
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


def test_scan_dmg_readonly(mocker):
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
                "filename": "Install Flash Player/.DS_Store",
                "size": "16388",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install Flash Player/Install Flash Player:rsrc",
                "size": "51737",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install Flash Player/Install Flash Player",
                "size": "33016",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install Flash Player/.VolumeIcon.icns",
                "size": "312349",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install Flash Player/.background.png",
                "size": "70758",
                "datetime": mock.ANY,
            },
        ],
        "meta": {
            "7zip_version": "24.09",
            "partitions": [
                {"path": mock.ANY, "type": "Dmg"},
                {"path": "4.apfs"},
                {
                    "path": "4.apfs",
                    "type": "APFS",
                    "created": mock.ANY,
                },
            ],
        },
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_readonly.dmg",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_dmg_readwrite(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 9, "extracted": 9},
        "files": [
            {
                "filename": ".DS_Store",
                "size": "6148",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install Flash Player/.DS_Store",
                "size": "16388",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install Flash Player/Install Flash Player:rsrc",
                "size": "51737",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install Flash Player/Install Flash Player",
                "size": "33016",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install Flash Player/.VolumeIcon.icns",
                "size": "312349",
                "datetime": mock.ANY,
            },
            {
                "filename": "Install Flash Player/.background.png",
                "size": "70758",
                "datetime": mock.ANY,
            },
            {
                "filename": ".fseventsd/fseventsd-uuid",
                "size": "36",
                "datetime": mock.ANY,
            },
            {
                "filename": ".fseventsd/0000000014ccc548",
                "size": "69",
                "datetime": mock.ANY,
            },
            {
                "filename": ".fseventsd/0000000014ccc549",
                "size": "72",
                "datetime": mock.ANY,
            },
        ],
        "meta": {
            "7zip_version": "24.09",
            "partitions": [
                {"path": mock.ANY, "type": "GPT"},
                {"path": "0.disk image.apfs", "file_system": "APFS"},
                {
                    "path": "0.disk image.apfs",
                    "type": "APFS",
                    "created": mock.ANY,
                },
            ],
        },
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_readwrite.dmg",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
