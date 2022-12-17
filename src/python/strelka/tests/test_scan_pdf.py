import datetime
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_pdf import ScanPdf


def test_scan_pdf(mocker):
    """
    This tests the ScanPdf scanner.
    It attempts to validate several given PDF metadata values.

    Pass: Sample event matches output of ScanPdf.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_pdf_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "images": 1,
        "lines": 34,
        "links": [],
        "words": 418,
        "author": "Ryan.OHoro",
        "creator": "Microsoft® Word 2016",
        "creation_date": "2022-12-16 13:48:52-06:00",
        "dirty": False,
        "embedded_files": {"count": 0, "names": []},
        "encrypted": False,
        "needs_pass": False,
        "format": "PDF 1.5",
        "keywords": "",
        "language": "en",
        "modify_date": "2022-12-16 13:48:52-06:00",
        "old_xrefs": True,
        "pages": 1,
        "producer": "Microsoft® Word 2016",
        "repaired": False,
        "subject": "",
        "title": "",
        "xrefs": 40,
        "phones": [],
        "objects": {},
    }

    scanner = ScanPdf(
        {"name": "ScanPdf", "key": "scan_pdf", "limits": {"scanner": 10}},
        "test_coordinate",
    )

    mocker.patch.object(ScanPdf, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test.pdf").read_bytes(),
        {"uid": "12345", "name": "somename"},
        {"scanner_timeout": 5},
        datetime.date.today(),
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_pdf_event, scanner.event)
