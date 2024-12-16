from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_seven_zip import ScanSevenZip as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_sevenzip(mocker):
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
                "filename": "hidden/lorem-hidden.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "hidden/lorem-readonly.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "hidden/lorem.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "lorem.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
        ],
        "hidden_dirs": ["hidden"],
        "meta": {"7zip_version": "24.09"},
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.7z",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_sevenzip_wordlist(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["wordlist", "cracked_by_wordlist"],
        "total": {"files": 4, "extracted": 4},
        "files": [
            {
                "filename": "hidden/lorem-hidden.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "hidden/lorem-readonly.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "hidden/lorem.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "lorem.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
        ],
        "hidden_dirs": ["hidden"],
        "meta": {"7zip_version": "24.09"},
        "cracked_password": b"password",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password.7z",
        options={
            "log_pws": True,
            "password_file": str(
                Path(Path(__file__).parent / "helpers/test_passwords.dat")
            ),
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_sevenzip_wordlist_filenames(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["wordlist", "cracked_by_wordlist"],
        "total": {"files": 4, "extracted": 4},
        "files": [
            {
                "filename": "hidden/lorem-hidden.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "hidden/lorem-readonly.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "hidden/lorem.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "lorem.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
        ],
        "hidden_dirs": ["hidden"],
        "meta": {"7zip_version": "24.09"},
        "cracked_password": b"password",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password_filenames.7z",
        options={
            "log_pws": True,
            "password_file": str(
                Path(Path(__file__).parent / "helpers/test_passwords.dat")
            ),
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_sevenzip_nocrack_filenames(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 0, "extracted": 0},
        "files": [],
        "hidden_dirs": [],
        "meta": {"7zip_version": "24.09"},
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password_filenames.7z",
        options={"crack_pws": False},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_sevenzip_msi_filenames(mocker):
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
                "datetime": "2022-12-12 04:12:56",
                "filename": "lorem.txt",
                "size": "4015",
            },
            {
                "datetime": "2022-12-12 04:12:56",
                "filename": "loremhidden.txt",
                "size": "4015",
            },
            {
                "datetime": "2022-12-12 04:12:56",
                "filename": "loremreadonly.txt",
                "size": "4015",
            },
        ],
        "hidden_dirs": [],
        "meta": {"7zip_version": "24.09"},
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.msi",
        options={"crack_pws": False},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_sevenzip_brute(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["wordlist", "incremental", "cracked_by_incremental"],
        "total": {"files": 4, "extracted": 4},
        "files": [
            {
                "filename": "hidden/lorem-hidden.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "hidden/lorem-readonly.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "hidden/lorem.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
            {
                "filename": "lorem.txt",
                "size": "4015",
                "datetime": "2022-12-12 03:12:55",
            },
        ],
        "hidden_dirs": ["hidden"],
        "meta": {"7zip_version": "24.09"},
        "cracked_password": b"aaa",
        "performance": {
            "keyspace": {"min_length": 1, "max_length": 3},
            "elapsed_seconds_wall": mock.ANY,
            "hashes_per_second": mock.ANY,
        },
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password_brute.7z",
        options={
            "scanner_timeout": 150,
            "log_pws": True,
            "brute_force": True,
            "min_length": 1,
            "max_length": 3,
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
