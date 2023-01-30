from pathlib import Path
from unittest import TestCase, mock

from pytest_unordered import unordered
from strelka.scanners.scan_capa import ScanCapa as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_capa_dotnet(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "matches": unordered(["contains PDB path", "compiled to the .NET platform"]),
        "mitre_ids": [],
        "mitre_techniques": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.exe",
        options={"scanner_timeout": 20},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_capa_elf(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "matches": [],
        "mitre_ids": [],
        "mitre_techniques": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.elf",
        options={"scanner_timeout": 20},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_capa_pe_xor(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "matches": unordered(
            [
                "encode data using XOR",
                "contains PDB path",
                "contain a resource (.rsrc) section",
                "parse PE header",
                "contain loop",
            ]
        ),
        "mitre_ids": unordered(["T1129", "T1027"]),
        "mitre_techniques": unordered(
            [
                "Execution::Shared Modules",
                "Defense Evasion::Obfuscated Files or Information",
            ]
        ),
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_xor.exe",
        options={"scanner_timeout": 20},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
