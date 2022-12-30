from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_encrypted_zip import ScanEncryptedZip as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_encrypted_zip(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["cracked_by_wordlist"],
        "total": {"files": 4, "extracted": 4},
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_zip_password.zip",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_encrypted_zip_aes256(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["cracked_by_wordlist"],
        "total": {"files": 4, "extracted": 4},
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_aes256_password.zip",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
