from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_x509 import ScanX509 as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_x509_pem(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "issuer": "C=US, ST=MN, L=Minneapolis, O=Target, CN=target.example.com",
        "subject": "C=US, ST=MN, L=Minneapolis, O=Target, CN=target.example.com",
        "serial_number": "46332118164471944499838906445041402559045013295",
        "fingerprint": "E8EC60C506A5383F5E0FC69FA7C9F460",
        "version": 0,
        "not_after": mock.ANY,
        "not_before": mock.ANY,
        "expired": mock.ANY,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pem",
        options={"type": "pem"},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_x509_der(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "issuer": "C=US, ST=MN, L=Minneapolis, O=Target, CN=target.example.com",
        "subject": "C=US, ST=MN, L=Minneapolis, O=Target, CN=target.example.com",
        "serial_number": "46332118164471944499838906445041402559045013295",
        "fingerprint": "E8EC60C506A5383F5E0FC69FA7C9F460",
        "version": 0,
        "not_after": mock.ANY,
        "not_before": mock.ANY,
        "expired": mock.ANY,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.der",
        options={"type": "der"},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
