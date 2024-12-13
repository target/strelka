from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_vhd import ScanVhd as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_vhd(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 3, "extracted": 3},
        "files": [
            {
                "filename": "System Volume Information/WPSettings.dat",
                "size": "12",
                "datetime": mock.ANY,
            },
            {
                "filename": "lorem.txt",
                "size": "4015",
                "datetime": mock.ANY,
            },
            {
                "filename": "$RECYCLE.BIN/S-1-5-21-3712961497-200595429-3248382696-1000/desktop.ini",
                "size": "129",
                "datetime": mock.ANY,
            },
        ],
        "hidden_dirs": [
            "System Volume Information",
            "$RECYCLE.BIN",
            "$RECYCLE.BIN/S-1-5-21-3712961497-200595429-3248382696-1000",
        ],
        "meta": {
            "7zip_version": "24.09",
            "partitions": [
                {"path": mock.ANY, "type": "GPT"},
                {"path": "0.Basic data partition.ntfs", "file_system": "Windows BDP"},
                {
                    "path": "0.Basic data partition.ntfs",
                    "type": "NTFS",
                    "label": "New Volume",
                    "file_system": "NTFS 3.1",
                    "created": mock.ANY,
                },
            ],
        },
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.vhd",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_vhdx(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 3, "extracted": 3},
        "files": [
            {
                "filename": "System Volume Information/WPSettings.dat",
                "size": "12",
                "datetime": mock.ANY,
            },
            {
                "filename": "lorem.txt",
                "size": "4015",
                "datetime": mock.ANY,
            },
            {
                "filename": "$RECYCLE.BIN/S-1-5-21-3712961497-200595429-3248382696-1000/desktop.ini",
                "size": "129",
                "datetime": mock.ANY,
            },
        ],
        "hidden_dirs": [
            "System Volume Information",
            "$RECYCLE.BIN",
            "$RECYCLE.BIN/S-1-5-21-3712961497-200595429-3248382696-1000",
        ],
        "meta": {
            "7zip_version": "24.09",
            "partitions": [
                {
                    "path": mock.ANY,
                    "type": "VHDX",
                    "creator_application": "Microsoft Windows 10.0.19044.0",
                },
                {"path": mock.ANY, "type": "GPT"},
                {"path": "0.Basic data partition.ntfs", "file_system": "Windows BDP"},
                {
                    "path": "0.Basic data partition.ntfs",
                    "type": "NTFS",
                    "label": "New Volume",
                    "file_system": "NTFS 3.1",
                    "created": mock.ANY,
                },
            ],
        },
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.vhdx",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
