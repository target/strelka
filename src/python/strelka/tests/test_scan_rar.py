from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_rar import ScanRar as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_rar(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 3, "extracted": 3},
        "host_os": "RAR_OS_WIN32",
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1484,
                "compression_rate": 63.04,
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1484,
                "compression_rate": 63.04,
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1484,
                "compression_rate": 63.04,
                "extracted": True,
                "encrypted": False,
            },
        ],
        "compression_rate": 63.04,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.rar",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_rar_file_limit(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["file_count_limit"],
        "total": {"files": 3, "extracted": 1},
        "host_os": "RAR_OS_WIN32",
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1484,
                "compression_rate": 63.04,
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1484,
                "compression_rate": 63.04,
                "extracted": False,
                "encrypted": False,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1484,
                "compression_rate": 63.04,
                "extracted": False,
                "encrypted": False,
            },
        ],
        "compression_rate": 63.04,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.rar",
        options={
            "limit": 1,
            "limit_metadata": False,
            "size_limit": 250000000,
            "crack_pws": True,
            "log_pws": True,
            "password_file": "/etc/strelka/passwords.dat",
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_rar_file_limit_no_meta(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["file_count_limit"],
        "total": {"files": 3, "extracted": 1},
        "host_os": "RAR_OS_WIN32",
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1484,
                "compression_rate": 63.04,
                "extracted": True,
                "encrypted": False,
            },
        ],
        "compression_rate": 63.04,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.rar",
        options={
            "limit": 1,
            "limit_metadata": True,
            "size_limit": 250000000,
            "crack_pws": True,
            "log_pws": True,
            "password_file": "/etc/strelka/passwords.dat",
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_rar_crack_pws_unencrypted(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 3, "extracted": 3},
        "host_os": "RAR_OS_WIN32",
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1484,
                "compression_rate": 63.04,
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1484,
                "compression_rate": 63.04,
                "extracted": True,
                "encrypted": False,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1484,
                "compression_rate": 63.04,
                "extracted": True,
                "encrypted": False,
            },
        ],
        "compression_rate": 63.04,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.rar",
        options={
            "limit": 1000,
            "limit_metadata": True,
            "size_limit": 250000000,
            "crack_pws": True,
            "log_pws": True,
            "password_file": "/etc/strelka/passwords.dat",
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_rar_password(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["password_protected"],
        "total": {"files": 3, "extracted": 3},
        "host_os": "RAR_OS_WIN32",
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": True,
                "encrypted": True,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": True,
                "encrypted": True,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": True,
                "encrypted": True,
            },
        ],
        "compression_rate": 62.94,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password.rar",
        options={
            "limit": 1000,
            "limit_metadata": True,
            "size_limit": 250000000,
            "crack_pws": True,
            "log_pws": False,
            "password_file": "/etc/strelka/passwords.dat",
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_rar_password_log_pwd(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["password_protected"],
        "password": "password",
        "total": {"files": 3, "extracted": 3},
        "host_os": "RAR_OS_WIN32",
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": True,
                "encrypted": True,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": True,
                "encrypted": True,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": True,
                "encrypted": True,
            },
        ],
        "compression_rate": 62.94,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password.rar",
        options={
            "limit": 1000,
            "limit_metadata": True,
            "size_limit": 250000000,
            "crack_pws": True,
            "log_pws": True,
            "password_file": "/etc/strelka/passwords.dat",
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_rar_password_crack_pws(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["password_protected", "no_password_match_found"],
        "total": {"files": 3, "extracted": 0},
        "host_os": "RAR_OS_WIN32",
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": False,
                "encrypted": True,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": False,
                "encrypted": True,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": False,
                "encrypted": True,
            },
        ],
        "compression_rate": 62.94,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password.rar",
        options={
            "limit": 1000,
            "limit_metadata": True,
            "size_limit": 250000000,
            "crack_pws": False,
            "log_pws": True,
            "password_file": "/etc/strelka/passwords.dat",
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_rar_password_bad_path(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["password_file_missing", "password_protected"],
        "total": {"files": 3, "extracted": 0},
        "host_os": "RAR_OS_WIN32",
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": False,
                "encrypted": True,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": False,
                "encrypted": True,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": False,
                "encrypted": True,
            },
        ],
        "compression_rate": 62.94,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password.rar",
        options={
            "limit": 1000,
            "limit_metadata": True,
            "size_limit": 250000000,
            "crack_pws": True,
            "log_pws": True,
            "password_file": "/etc/strelka/nosuchfile",
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_rar_password_empty_file(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["no_passwords_loaded", "password_protected"],
        "total": {"files": 3, "extracted": 0},
        "host_os": "RAR_OS_WIN32",
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": False,
                "encrypted": True,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": False,
                "encrypted": True,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1488,
                "compression_rate": 62.94,
                "extracted": False,
                "encrypted": True,
            },
        ],
        "compression_rate": 62.94,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_password.rar",
        options={
            "limit": 1000,
            "limit_metadata": True,
            "size_limit": 250000000,
            "crack_pws": True,
            "log_pws": True,
            "password_file": Path(__file__).parent / "fixtures/test.empty",
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_rar_big(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["file_size_limit"],
        "total": {"files": 1, "extracted": 0},
        "host_os": "RAR_OS_WIN32",
        "files": [
            {
                "file_name": "test_big.zero",
                "file_size": 512000000,
                "compression_size": 20674,
                "compression_rate": 100.0,
                "extracted": False,
                "encrypted": False,
            },
        ],
        "compression_rate": 100.0,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_big.rar",
        options={
            "limit": 1000,
            "limit_metadata": True,
            "size_limit": 511999999,
            "crack_pws": True,
            "log_pws": True,
            "password_file": "/etc/strelka/passwords.dat",
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
