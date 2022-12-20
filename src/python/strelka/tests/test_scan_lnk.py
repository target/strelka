import datetime
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_lnk import ScanLNK


def test_scan_lnk(mocker):
    """
    This tests the ScanLNK scanner.
    It attempts to validate several given LNK metadata values.

    Pass: Metadata values from file match specified values.
    Failure: Unable to load file or metadata values do not match specified values.
    """

    test_scan_lnk_event = {
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

    scanner = ScanLNK(
        {"name": "ScanLNK", "key": "scan_lnk", "limits": {"scanner": 10}},
        "test_coordinate",
    )

    mocker.patch.object(ScanLNK, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test.lnk").read_bytes(),
        {"uid": "12345", "name": "somename"},
        {"scanner_timeout": 5},
        datetime.date.today(),
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_lnk_event, scanner.event)
