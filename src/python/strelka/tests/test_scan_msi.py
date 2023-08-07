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
        "ExifToolVersion": mock.ANY,
        "FileName": mock.ANY,
        "Directory": "/tmp",
        "FileSize": mock.ANY,
        "FileModifyDate": mock.ANY,
        "FileAccessDate": mock.ANY,
        "FileInodeChangeDate": mock.ANY,
        "FilePermissions": mock.ANY,
        "FileType": "FPX",
        "FileTypeExtension": "fpx",
        "MIMEType": "image/vnd.fpx",
        "CodePage": "Windows Latin 1 (Western European)",
        "Title": "Installation Database",
        "Subject": "StrelkaMSITest",
        "Author": "Target",
        "Keywords": "Installer",
        "Comments": "This installer database contains the logic and data required to install StrelkaMSITest.",
        "Template": "Intel;1033",
        "RevisionNumber": "{3F5D9FF7-E061-48CF-95B2-0AA7C9E5DE2A}",
        "CreateDate": mock.ANY,
        "ModifyDate": mock.ANY,
        "Pages": 200,
        "Words": 2,
        "Software": "Windows Installer XML Toolset (3.11.2.4516)",
        "Security": "Read-only recommended",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.msi",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
