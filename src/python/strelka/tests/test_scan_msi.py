from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_msi import ScanMsi as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_msi(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "SourceFile": mock.ANY,
        "ExifToolVersion": 12.52,
        "FileName": mock.ANY,
        "Directory": mock.ANY,
        "FileSize": "3.6 kB",
        "FileModifyDate": mock.ANY,
        "FileAccessDate": mock.ANY,
        "FileInodeChangeDate": mock.ANY,
        "FilePermissions": mock.ANY,
        "FileType": "FPX",
        "FileTypeExtension": "fpx",
        "MIMEType": "image/vnd.fpx",
        "CodePage": "Windows Latin 1 (Western European)",
        "Title": "Installation Database",
        "Subject": "Microsoft WSE 3.0",
        "Author": "Microsoft Corporation",
        "Keywords": "Installer,MSI,Database",
        "Comments": "",
        "CreateDate": mock.ANY,
        "Software": "InstallShield® X - Professional Edition 10.0",
        "Security": "Password protected",
        "Template": "Intel;1033",
        "LastModifiedBy": "Intel;1033",
        "RevisionNumber": "{EDEA8AB7-7683-4ED2-AA19-E6C078064C0D}3.0.5305.0;{EDEA8AB7-7683-4ED2-AA19-E6C078064C0D}3.0.5305.0;{B4BB35AA-51EC-41A5-9C85-90D6FA98968C}",
        "Pages": 200,
        "Characters": 0,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.msi",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
