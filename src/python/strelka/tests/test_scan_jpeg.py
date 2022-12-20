import datetime
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_jpeg import ScanJpeg


def test_scan_jpeg(mocker):
    """
    This tests the ScanJpeg scanner.
    It attempts to validate several given JPEG metadata values.

    Pass: Sample event matches output of ScanJpeg.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_jpeg_event = {"elapsed": mock.ANY, "flags": []}

    scanner = ScanJpeg(
        {"name": "ScanJpeg", "key": "scan_jpeg", "limits": {"scanner": 10}},
        "test_coordinate",
    )

    mocker.patch.object(ScanJpeg, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test.jpg").read_bytes(),
        {"uid": "12345", "name": "somename"},
        {"scanner_timeout": 5},
        datetime.date.today(),
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_jpeg_event, scanner.event)


def test_scan_jpeg_pe_overlay(mocker):
    """
    This tests the ScanJpeg scanner.
    It attempts to validate several given JPEG metadata values.

    Pass: Sample event matches output of ScanJpeg.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_jpeg_event = {"elapsed": mock.ANY, "flags": [], "trailer_index": 308564}

    scanner = ScanJpeg(
        {"name": "ScanJpeg", "key": "scan_jpeg", "limits": {"scanner": 10}},
        "test_coordinate",
    )

    mocker.patch.object(ScanJpeg, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test_pe_overlay.jpg").read_bytes(),
        {"uid": "12345", "name": "somename"},
        {"scanner_timeout": 5},
        datetime.date.today(),
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_jpeg_event, scanner.event)
