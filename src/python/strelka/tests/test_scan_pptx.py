from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_pptx import ScanPptx as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_pptx(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "author": "",
        "category": "",
        "comments": "generated using python-pptx",
        "content_status": "",
        "created": mock.ANY,
        "identifier": "",
        "keywords": "",
        "language": "",
        "last_modified_by": "Test Author",
        "modified": mock.ANY,
        "revision": 1,
        "subject": "",
        "title": "",
        "version": "",
        "slide_count": 4,
        "word_count": mock.ANY,
        "image_count": 1,
        "hyperlinks": [
            "https://test.tracking-domain.example.com/click/https%3A%2F%2Fphishing.example.com%2Flogin/tracking-id-12345#6a6f686e2e646f65406578616d706c652e636f6d"
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pptx",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_pptx_extracts_text(mocker):
    """
    Pass: Text extraction produces expected content.
    Failure: Text not extracted or content doesn't match.
    """

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pptx",
        options={"extract_text": True},
    )

    # Verify slide count and word count are populated
    assert scanner_event.get("slide_count") == 4
    assert scanner_event.get("word_count") == 307
    assert scanner_event.get("image_count") == 1


def test_scan_pptx_extracts_hyperlinks(mocker):
    """
    Pass: Hyperlinks are extracted from the presentation.
    Failure: Hyperlinks not found or malformed.
    """

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pptx",
    )

    # Verify hyperlinks are captured (sanitized test URLs)
    hyperlinks = scanner_event.get("hyperlinks", [])
    assert len(hyperlinks) == 1
    assert "tracking-domain.example.com" in hyperlinks[0]
    assert "phishing.example.com" in hyperlinks[0]

