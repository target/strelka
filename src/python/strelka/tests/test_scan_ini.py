from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_ini import ScanIni as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_ini(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "comments": [
            b"; Lorem ipsum dolor sit amet, consectetur adipiscing elit,",
            b";sed do eiusmod tempor incididunt ut labore et dolore magna",
            b";aliqua.",
            b"# Elementum sagittis vitae et leo duis ut diam.",
            b"# Nulla facilisi etiam dignissim diam quis.",
        ],
        "keys": [
            {"section": b"Lorem", "name": b"Update", "value": b"300"},
            {"section": b"Lorem", "name": b"Repeat", "value": b"24"},
            {"section": b"Ipsum", "name": b"Name", "value": b"Lorem Ipsum"},
            {"section": b"Ipsum", "name": b"Author", "value": b"Lorem"},
            {
                "section": b"Ipsum",
                "name": b"Information",
                "value": b"Volutpat commodo sed egestas egestas.",
            },
            {"section": b"Ipsum", "name": b"License", "value": b"Ipsum"},
            {"section": b"Ipsum", "name": b"Version", "value": b"1.0.1"},
        ],
        "sections": [b"Lorem", b"Ipsum"],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.ini",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
