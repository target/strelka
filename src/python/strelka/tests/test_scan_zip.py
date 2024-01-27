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
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "hidden/lorem.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
                "extracted": True,
                "encrypted": False,
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


def test_scan_zip_count_limit(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["file_count_limit"],
        "total": {"files": 4, "extracted": 2},
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
                "extracted": True,
                "encrypted": False,
            },
        ],
        "compression_rate": 64.51,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.zip",
        options={"limit": 2},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_zip_metadata_limit(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["file_count_limit"],
        "total": {"files": 4, "extracted": 2},
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "hidden/lorem.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
                "extracted": False,
                "encrypted": False,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
                "extracted": False,
                "encrypted": False,
            },
        ],
        "compression_rate": 64.51,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.zip",
        options={
            "limit": 2,
            "limit_metadata": False,
        },
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
        "total": {"files": 4, "extracted": 4},
        "password": ["password"],
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1453,
                "compression_rate": 63.81,
                "extracted": True,
                "encrypted": True,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1453,
                "compression_rate": 63.81,
                "extracted": True,
                "encrypted": True,
            },
            {
                "file_name": "hidden/lorem.txt",
                "file_size": 4015,
                "compression_size": 1453,
                "compression_rate": 63.81,
                "extracted": True,
                "encrypted": True,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1453,
                "compression_rate": 63.81,
                "extracted": True,
                "encrypted": True,
            },
        ],
        "compression_rate": 63.81,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_aes256_password.zip",
        options={"crack_pws": True, "log_pws": True},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_zip_big(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["file_size_limit"],
        "total": {"files": 1, "extracted": 0},
        "files": [
            {
                "file_name": "test_big.zero",
                "file_size": 512000000,
                "compression_size": 496891,
                "compression_rate": 99.9,
                "extracted": False,
                "encrypted": False,
            },
        ],
        "compression_rate": 99.9,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_big.zip",
        options={"size_limit": 100000000},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_zip_empty(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 2, "extracted": 1},
        "files": [
            {
                "file_name": "test_empty.bin",
                "file_size": 0,
                "compression_size": 0,
                "compression_rate": 0,
                "extracted": False,
                "encrypted": False,
            },
            {
                "file_name": "test.txt",
                "file_size": 4007,
                "compression_size": 1449,
                "compression_rate": 63.84,
                "extracted": True,
                "encrypted": False,
            },
        ],
        "compression_rate": 63.84,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_empty.zip",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_zip_mixed_zipcrypto(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["encrypted"],
        "total": {"files": 4, "extracted": 3},
        "password": ["password"],
        "files": [
            {
                "file_name": "test.txt",
                "file_size": 4007,
                "compression_size": 1421,
                "compression_rate": 64.54,
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "test_aes256.txt",
                "file_size": 4007,
                "compression_size": 1449,
                "compression_rate": 63.84,
                "extracted": True,
                "encrypted": True,
            },
            {
                "file_name": "test_zipcrypto.txt",
                "file_size": 4007,
                "compression_size": 1433,
                "compression_rate": 64.24,
                "extracted": True,
                "encrypted": True,
            },
            {
                "file_name": "test_zipcrypto_badpw.txt",
                "file_size": 4007,
                "compression_size": 1433,
                "compression_rate": 64.24,
                "extracted": False,
                "encrypted": True,
            },
        ],
        "compression_rate": 64.21,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_mixedcrypto.zip",
        options={"crack_pws": True, "log_pws": True},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


# test_aes256_password.zip
