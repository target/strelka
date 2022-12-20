from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_html import ScanHtml as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_html(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {
            "scripts": 2,
            "forms": 0,
            "inputs": 0,
            "frames": 0,
            "extracted": 0,
            "spans": 35,
        },
        "title": "Lorem Ipsum",
        "hyperlinks": [],
        "forms": [],
        "frames": [],
        "inputs": [],
        "scripts": [
            {
                "src": "https://example.com/example.js",
                "language": None,
                "type": "text/javascript",
            },
            {"src": None, "language": None, "type": None},
        ],
        "spans": [
            {"class": None, "style": "font-size:11pt"},
            {"class": None, "style": "background-color:white"},
            {"class": None, "style": "font-family:Calibri,sans-serif"},
            {"class": None, "style": "font-size:52.5pt"},
            {"class": None, "style": "color:black"},
            {"class": None, "style": "font-size:12pt"},
            {"class": None, "style": 'font-family:"Times New Roman",serif'},
            {"class": None, "style": "font-size:10.5pt"},
            {"class": None, "style": 'font-family:"Arial",sans-serif'},
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.html",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
