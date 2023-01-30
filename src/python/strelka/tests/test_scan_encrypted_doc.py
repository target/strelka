from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_encrypted_doc import ScanEncryptedDoc as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_encrypted_doc(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["cracked_by_wordlist"],
        "cracked_password": b"Password1!",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password.doc",
        options={
            "log_pws": True,
            "password_file": str(
                Path(Path(__file__).parent / "helpers/test_passwords.dat")
            ),
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_encrypted_docx(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["cracked_by_wordlist"],
        "cracked_password": b"Password1!",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password.docx",
        options={
            "log_pws": True,
            "password_file": str(
                Path(Path(__file__).parent / "helpers/test_passwords.dat")
            ),
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_encrypted_doc_brute(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["cracked_by_incremental"],
        "cracked_password": b"aaa",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password_brute.doc",
        options={
            "scanner_timeout": 120,
            "log_pws": True,
            "brute_force": True,
            "min_length": 1,
            "max_length": 3,
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_encrypted_docx_brute(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["cracked_by_incremental"],
        "cracked_password": b"aaa",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password_brute.docx",
        options={
            "scanner_timeout": 120,
            "log_pws": True,
            "brute_force": True,
            "min_length": 1,
            "max_length": 3,
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
