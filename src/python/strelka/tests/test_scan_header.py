from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_header import ScanHeader as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_header(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "header": b"Lorem ipsum dolor sit amet, consectetur adipiscing",
        "backslash": "Lorem ipsum dolor sit amet, consectetur adipiscing",
        "hex": b"4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e67",
        "raw": b"Lorem ipsum dolor sit amet, consectetur adipiscing",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.txt",
        options={"encodings": ["classic", "raw", "hex", "backslash"]},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_header_exe(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "header": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "backslash": "MZ\\x90\\x00\\x03\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\xff\\xff\\x00\\x00\\xb8\\x00\\x00\\x00\\x00\\x00\\x00\\x00@\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00",
        "hex": b"4d5a90000300000004000000ffff0000b8000000000000004000000000000000000000000000000000000000000000000000",
        "raw": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.exe",
        options={"encodings": ["classic", "raw", "hex", "backslash"]},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
