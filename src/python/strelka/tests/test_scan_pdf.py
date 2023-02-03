from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_pdf import ScanPdf as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_pdf(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "images": 1,
        "lines": 34,
        "links": [],
        "words": 418,
        "author": "Ryan.OHoro",
        "creator": "Microsoft® Word 2016",
        "creation_date": "2022-12-16T19:48:52Z",
        "dirty": False,
        "embedded_files": {"count": 0, "names": []},
        "encrypted": False,
        "needs_pass": False,
        "format": "PDF 1.5",
        "keywords": "",
        "language": "en",
        "modify_date": "2022-12-16T19:48:52Z",
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

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pdf",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
