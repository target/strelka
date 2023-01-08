from pathlib import Path
from pytest_unordered import unordered
from unittest import TestCase, mock

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
        options={"location": "/etc/capa/"},
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
        options={"location": "/etc/capa/"},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)

