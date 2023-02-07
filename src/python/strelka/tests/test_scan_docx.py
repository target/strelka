from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_docx import ScanDocx as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_docx(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "author": "Ryan.OHoro",
        "category": "",
        "comments": "",
        "content_status": "",
        "created": "2022-12-16T16:28:00",
        "identifier": "",
        "keywords": "",
        "language": "",
        "last_modified_by": "Ryan.OHoro",
        "modified": "2022-12-16T16:44:00",
        "revision": 2,
        "subject": "",
        "title": "",
        "version": "",
        "font_colors": ["", "000000"],
        "word_count": 413,
        "image_count": 1,
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.docx",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
