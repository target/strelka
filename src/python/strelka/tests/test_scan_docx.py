import datetime
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_docx import ScanDocx


def test_scan_docx(mocker):
    """
    This tests the ScanDocx scanner.
    It attempts to validate several given DOCX metadata values.

    Pass: Sample event matches output of ScanDocx.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_docx_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "author": "Ryan.OHoro",
        "category": "",
        "comments": "",
        "content_status": "",
        "created": 1671208080,
        "identifier": "",
        "keywords": "",
        "language": "",
        "last_modified_by": "Ryan.OHoro",
        "modified": 1671209040,
        "revision": 2,
        "subject": "",
        "title": "",
        "version": "",
        "font_colors": ["", "000000"],
        "word_count": 413,
        "image_count": 1,
    }

    scanner = ScanDocx(
        {"name": "ScanDocx", "key": "scan_docx", "limits": {"scanner": 10}},
        "test_coordinate",
    )

    mocker.patch.object(ScanDocx, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test.docx").read_bytes(),
        {"uid": "12345", "name": "somename"},
        {"scanner_timeout": 5},
        datetime.date.today(),
    )

    print(scanner.event)

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_docx_event, scanner.event)
