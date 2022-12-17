import datetime
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_encrypted_zip import ScanEncryptedZip


def test_scan_encrypted_zip(mocker):
    """
    This tests the ScanEncryptedZip scanner with a ZipCrypto protected ZIP file, password "password".

    Pass: Sample event matches output of ScanEncryptedZip.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_encrypted_zip_event = {
        "elapsed": mock.ANY,
        "flags": ["cracked_by_wordlist"],
        "total": {"files": 4, "extracted": 4}
    }

    scanner = ScanEncryptedZip(
        {"name": "ScanEncryptedZip", "key": "scan_zip", "limits": {"scanner": 10}},
        "test_coordinate",
    )

    mocker.patch.object(ScanEncryptedZip, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test_zip_password.zip").read_bytes(),
        {"uid": "12345", "name": "somename"},
        {"scanner_timeout": 5},
        datetime.date.today(),
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_encrypted_zip_event, scanner.event)
