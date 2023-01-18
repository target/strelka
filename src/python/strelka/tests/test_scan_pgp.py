from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_pgp import ScanPgp as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_pgp_sig_asc(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "public_key_encrypted_session_keys": [],
        "public_keys": [],
        "secret_keys": [],
        "trusts": [],
        "user_attributes": [],
        "user_ids": [],
        "signatures": [
            {
                "creation_time": "2023-01-16T01:26:37",
                "hash_algorithm": "SHA512",
                "key_id": b"CA352AC023CAA9FF",
                "length": 435,
                "pub_algorithm": "RSA Encrypt or Sign",
                "sig_type": "Signature of a canonical text document",
                "sig_version": 4,
            }
        ],
        "total": {
            "public_key_encrypted_session_keys": 0,
            "public_keys": 0,
            "secret_keys": 0,
            "signatures": 1,
            "trusts": 0,
            "user_attributes": 0,
            "user_ids": 0,
        },
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.txt.asc",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_pgp_key_public(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {
            "public_keys": 2,
            "public_key_encrypted_session_keys": 0,
            "secret_keys": 0,
            "signatures": 2,
            "trusts": 0,
            "user_attributes": 0,
            "user_ids": 1,
        },
        "public_keys": [
            {
                "key_id": b"CA352AC023CAA9FF",
                "pubkey_version": 4,
                "fingerprint": b"E96BBA8B1BBC8949B4113A60CA352AC023CAA9FF",
                "pub_algorithm_type": "rsa",
                "key_value": None,
                "creation_time": "2023-01-16T01:18:17",
            },
            {
                "key_id": b"1DA06DD036BE9849",
                "pubkey_version": 4,
                "fingerprint": b"DA3448C5EF7EC804DD0C29681DA06DD036BE9849",
                "pub_algorithm_type": "rsa",
                "key_value": None,
                "creation_time": "2023-01-16T01:18:17",
            },
        ],
        "public_key_encrypted_session_keys": [],
        "secret_keys": [],
        "signatures": [
            {
                "key_id": b"CA352AC023CAA9FF",
                "sig_version": 4,
                "sig_type": "Positive certification of a User ID and Public Key packet",
                "hash_algorithm": "SHA512",
                "pub_algorithm": "RSA Encrypt or Sign",
                "length": 468,
                "creation_time": "2023-01-16T01:18:17",
            },
            {
                "key_id": b"CA352AC023CAA9FF",
                "sig_version": 4,
                "sig_type": "Subkey Binding Signature",
                "hash_algorithm": "SHA512",
                "pub_algorithm": "RSA Encrypt or Sign",
                "length": 444,
                "creation_time": "2023-01-16T01:18:17",
            },
        ],
        "trusts": [],
        "user_attributes": [],
        "user_ids": [
            {
                "user": "Exam Ple <example@example.com>",
                "user_name": "Exam Ple",
                "user_email": "example@example.com",
            }
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_public.pgp",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_pgp_private(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {
            "public_keys": 0,
            "public_key_encrypted_session_keys": 0,
            "secret_keys": 2,
            "signatures": 2,
            "trusts": 0,
            "user_attributes": 0,
            "user_ids": 1,
        },
        "public_keys": [],
        "public_key_encrypted_session_keys": [],
        "secret_keys": [
            {
                "key_id": b"A524C36DDD5A047E",
                "pubkey_version": None,
                "fingerprint": b"1D532537AD441C693336CF93A524C36DDD5A047E",
                "pub_algorithm_type": None,
                "key_value": None,
                "creation_time": "2023-01-16T01:18:17",
            },
            {
                "key_id": b"CD9EC4434EE89B84",
                "pubkey_version": None,
                "fingerprint": b"927F437CDFF227650A2E27EBCD9EC4434EE89B84",
                "pub_algorithm_type": None,
                "key_value": None,
                "creation_time": "2023-01-16T01:18:17",
            },
        ],
        "signatures": [
            {
                "key_id": b"CA352AC023CAA9FF",
                "sig_version": 4,
                "sig_type": "Positive certification of a User ID and Public Key packet",
                "hash_algorithm": "SHA512",
                "pub_algorithm": "RSA Encrypt or Sign",
                "length": 468,
                "creation_time": "2023-01-16T01:18:17",
            },
            {
                "key_id": b"CA352AC023CAA9FF",
                "sig_version": 4,
                "sig_type": "Subkey Binding Signature",
                "hash_algorithm": "SHA512",
                "pub_algorithm": "RSA Encrypt or Sign",
                "length": 444,
                "creation_time": "2023-01-16T01:18:17",
            },
        ],
        "trusts": [],
        "user_attributes": [],
        "user_ids": [
            {
                "user": "Exam Ple <example@example.com>",
                "user_name": "Exam Ple",
                "user_email": "example@example.com",
            }
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_private.pgp",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_pgp_sig(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {
            "public_keys": 0,
            "public_key_encrypted_session_keys": 0,
            "secret_keys": 0,
            "signatures": 1,
            "trusts": 0,
            "user_attributes": 0,
            "user_ids": 0,
        },
        "public_keys": [],
        "public_key_encrypted_session_keys": [],
        "secret_keys": [],
        "signatures": [
            {
                "key_id": b"05D98505AB15E3AB",
                "sig_version": 4,
                "sig_type": "Signature of a binary document",
                "hash_algorithm": "SHA512",
                "pub_algorithm": "RSA Encrypt or Sign",
                "length": 435,
                "creation_time": "2023-01-16T00:33:03",
            }
        ],
        "trusts": [],
        "user_attributes": [],
        "user_ids": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.txt.gpg",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
