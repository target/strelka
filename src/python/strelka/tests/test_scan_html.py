import datetime
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_html import ScanHtml


def test_scan_html(mocker):
    """
    This tests the ScanHtml scanner.
    It attempts to validate several given HTML metadata values.

    Pass: Sample event matches output of ScanHtml.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_html_event = {
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

    scanner = ScanHtml(
        {"name": "ScanHtml", "key": "scan_html", "limits": {"scanner": 10}},
        "test_coordinate",
    )

    mocker.patch.object(ScanHtml, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test.html").read_bytes(),
        {"uid": "12345", "name": "somename"},
        {"scanner_timeout": 5},
        datetime.date.today(),
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_html_event, scanner.event)
