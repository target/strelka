from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_lnk import ScanLNK as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_lnk(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "drive_type": mock.ANY,  # EnumIntegerString.new(3, "DRIVE_FIXED"),
        "drive_serial_number": "a6e696c8",
        "volume_label": "FOOBAR",
        "local_base_path": "C:\\Windows\\System32\\notepad.exe",
        "working_dir": "C:\\Windows\\System32",
        "machine_id": b"desktop-s4hcuuq",
        "mac": "fc44827c0fbe",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.lnk",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
