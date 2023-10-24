from pathlib import Path
from unittest import TestCase, mock

import pytest
from strelka.scanners.scan_qr import ScanQr as ScanUnderTest
from strelka.tests import run_test_scan

formats = {
    "test_qr_email.png": {"data": "mailto:email@example.com?subject=Subject&body=Body"},
    "test_qr_epc.png": {
        "data": "BCD\n002\n1\nSCT\nRLNWATWW\nDoctors Without Borders\nAT973200000000518548\n\n\n\nEmergency Donation\nEmergency aid donation - MSF"
    },
    "test_qr_event.png": {
        "data": "BEGIN:VEVENT\nSUMMARY:My Event\nDESCRIPTION:Description\nLOCATION:Location\nDTSTART:20231017T222901Z\nEND:VEVENT"
    },
    "test_qr_mecard.png": {
        "data": "MECARD:N:John Doe;TEL:555-555-5555;EMAIL:email@example.com;NOTE:Contoso;URL:https://www.example.com;"
    },
    "test_qr_phone.png": {"data": "tel:555-555-5555"},
    "test_qr_raw.png": {"data": "Plain Text Code"},
    "test_qr_sms.png": {"data": "smsto:555-555-5555:Message"},
    "test_qr_url.png": {"data": "https://www.example.com/"},
    "test_qr_vcard.png": {
        "data": "BEGIN:VCARD\r\nVERSION:3.0\r\nFN;CHARSET=UTF-8:John Doe\r\nN;CHARSET=UTF-8:Doe;John;;;\r\nTEL;TYPE=HOME,VOICE:555-555-5555\r\nTEL;TYPE=WORK,VOICE:666-666-6666\r\nEMAIL:email@example.com\r\nURL:https://www.example.com\r\nEND:VCARD"
    },
    "test_qr_wifi.png": {"data": "WIFI:T:WPA;S:SSID;P:password;;"},
}


@pytest.mark.parametrize("format", formats.keys())
def test_scan_qr(mocker, format):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "type": mock.ANY,
    }

    test_scan_event.update(formats[format])

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / f"fixtures/{format}",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_qr_jpg(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "data": "https://www.example.com/",
        "type": "url",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_qr.png",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_qr_png(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "data": "https://www.example.com/",
        "type": "url",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_qr.png",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_qr_webp(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "data": "https://www.example.com/",
        "type": "url",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_qr.webp",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
