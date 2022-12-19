from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_manifest import ScanManifest as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_manifest(mocker):
    """
    Pass: Sample event matches output of the scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "name": "Focus Mode",
        "manifest_version": 3,
        "version": "1.0",
        "description": "Enable reading mode on Chrome's official Extensions and Chrome Web Store documentation.",
        "permissions": ["scripting", "activeTab"],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_manifest.json",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
