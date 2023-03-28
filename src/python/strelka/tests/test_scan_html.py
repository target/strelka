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
            "extracted": 1,
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
            {
                "class": None,
                "style": "font-family:Calibri,sans-serif",
            },
            {"class": None, "style": "font-size:52.5pt"},
            {"class": None, "style": "color:black"},
            {"class": None, "style": "font-size:12pt"},
            {
                "class": None,
                "style": 'font-family:"Times New Roman",serif',
            },
            {"class": None, "style": "font-size:10.5pt"},
            {
                "class": None,
                "style": 'font-family:"Arial",sans-serif',
            },
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.html",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_html_max_hyperlinks(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    MAX_SIZE_OPTION = 5

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {
            "scripts": 0,
            "forms": 0,
            "inputs": 0,
            "frames": 0,
            "extracted": 0,
            "spans": 0,
        },
        "title": "Sample HTML File",
        "hyperlinks_count": 7,
        "hyperlinks": [
            "https://www.example.com",
            "https://www.example2.com",
            "https://www.example3.com",
            "https://www.example.com/downloads/example.pdf",
            "https://www.example.com/images/example.jpg",
        ],
        "forms": [],
        "frames": [],
        "inputs": [],
        "scripts": [],
        "spans": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_hyperlinks.html",
        options={"max_hyperlinks": MAX_SIZE_OPTION},
    )

    TestCase.maxDiff = None
    TestCase().assertLessEqual(len(test_scan_event["hyperlinks"]), MAX_SIZE_OPTION)
    TestCase().assertTrue(
        test_scan_event["hyperlinks_count"],
        scanner_event["hyperlinks_count"],
    )
