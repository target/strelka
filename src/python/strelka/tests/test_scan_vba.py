from pathlib import Path
from unittest import TestCase, mock

from pytest_unordered import unordered

from strelka.scanners.scan_vba import ScanVba as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_vba(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """
    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "auto_exec": ["AutoOpen", "Document_Open"],
        "base64": [],
        "dridex": [],
        "hex": [],
        "ioc": [
            "https://www.test.example.com",
            "https://www.test.com/test.bat",
            "test.bat",
        ],
        "iocs": unordered(
            [
                {"ioc": "test.bat", "ioc_type": "domain", "scanner": "ScanVba"},
                {
                    "ioc": "www.test.example.com",
                    "ioc_type": "domain",
                    "scanner": "ScanVba",
                },
                {
                    "ioc": "https://www.test.example.com",
                    "ioc_type": "url",
                    "scanner": "ScanVba",
                },
                {"ioc": "www.test.com", "ioc_type": "domain", "scanner": "ScanVba"},
                {
                    "ioc": "https://www.test.com/test.bat",
                    "ioc_type": "url",
                    "scanner": "ScanVba",
                },
            ]
        ),
        "suspicious": ["powershell", "Start-Process", "ShowWindow", "GetObject"],
        "total": {"extracted": 1, "files": 1},
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.vba",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
