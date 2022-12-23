from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_zip import ScanZip as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_zip(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 4, "extracted": 4},
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
            },
            {
                "file_name": "hidden/lorem.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
            },
        ],
        "compression_rate": 64.51,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.zip",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_zip_aes256(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["encrypted"],
        "total": {"files": 4, "extracted": 0},
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1453,
                "compression_rate": 63.81,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1453,
                "compression_rate": 63.81,
            },
            {
                "file_name": "hidden/lorem.txt",
                "file_size": 4015,
                "compression_size": 1453,
                "compression_rate": 63.81,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1453,
                "compression_rate": 63.81,
            },
        ],
        "compression_rate": 63.81,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_aes256_password.zip",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
