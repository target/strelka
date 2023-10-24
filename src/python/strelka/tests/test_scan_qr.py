from pathlib import Path
from unittest import TestCase, mock

import pytest

from strelka.scanners.scan_qr import ScanQr as ScanUnderTest
from strelka.tests import run_test_scan

formats = {
    "test_qr.jpg": {"flags": [], "data": ["https://www.example.com/"]},
    "test_qr.png": {"flags": [], "data": ["https://www.example.com/"]},
    "test_qr.webp": {"flags": [], "data": ["https://www.example.com/"]},
    "test_qr_email.png": {
        "flags": [],
        "data": ["mailto:email@example.com?subject=Subject&body=Body"],
    },
    "test_qr_epc.png": {
        "flags": [],
        "data": [
            "BCD\n002\n1\nSCT\nRLNWATWW\nDoctors Without Borders\nAT973200000000518548\n\n\n\nEmergency Donation\nEmergency aid donation - MSF"
        ],
    },
    "test_qr_event.png": {
        "flags": [],
        "data": [
            "BEGIN:VEVENT\nSUMMARY:My Event\nDESCRIPTION:Description\nLOCATION:Location\nDTSTART:20231017T222901Z\nEND:VEVENT"
        ],
    },
    "test_qr_mecard.png": {
        "flags": [],
        "data": [
            "MECARD:N:John Doe;TEL:555-555-5555;EMAIL:email@example.com;NOTE:Contoso;URL:https://www.example.com;"
        ],
    },
    "test_qr_multi.png": {
        "flags": [],
        "data": ["https://www.example.com/", "Plain Text Code"],
    },
    "test_qr_multi_inverted.png": {
        "flags": ["inverted"],
        "data": ["https://www.example.com/", "Plain Text Code"],
    },
    "test_qr_phone.png": {"flags": [], "data": ["tel:555-555-5555"]},
    "test_qr_raw.png": {"flags": [], "data": ["Plain Text Code"]},
    "test_qr_sms.png": {"flags": [], "data": ["smsto:555-555-5555:Message"]},
    "test_qr_url.png": {"flags": [], "data": ["https://www.example.com/"]},
    "test_qr_vcard.png": {
        "flags": [],
        "data": [
            "BEGIN:VCARD\r\nVERSION:3.0\r\nFN;CHARSET=UTF-8:John Doe\r\nN;CHARSET=UTF-8:Doe;John;;;\r\nTEL;TYPE=HOME,VOICE:555-555-5555\r\nTEL;TYPE=WORK,VOICE:666-666-6666\r\nEMAIL:email@example.com\r\nURL:https://www.example.com\r\nEND:VCARD"
        ],
    },
    "test_qr_wifi.png": {"flags": [], "data": ["WIFI:T:WPA;S:SSID;P:password;;"]},
}


@pytest.mark.parametrize("fmt", formats.keys())
def test_scan_qr(mocker, fmt):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
    }

    test_scan_event.update(formats[fmt])

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / f"fixtures/{fmt}",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_qr_support_inverted_true(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["inverted"],
        "data": ["Plain Text Code"],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_qr_inverted.png",
        options={"support_inverted": True},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_qr_support_inverted_false(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {"elapsed": mock.ANY, "flags": [], "data": []}

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_qr_inverted.png",
        options={"support_inverted": False},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
