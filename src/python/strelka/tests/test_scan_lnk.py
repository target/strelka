from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_lnk import ScanLnk as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_lnk(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "drive_type": "DRIVE_FIXED",
        "drive_serial_number": "c2922660",
        "volume_label": "Local Disk",
        "local_base_path": "C:\\Windows\\System32\\calc.exe",
        "name_string": "Test Comment",
        "relative_path": "..\\..\\..\\..\\Windows\\System32\\calc.exe",
        "working_dir": "C:\\Windows\\System32",
        "command_line_args": "-testCommands",
        "machine_id": b"laptop-c77ajnj7",
        "mac": "38fc989e18fc",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.lnk",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
