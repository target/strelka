from pathlib import Path
from unittest import TestCase, mock

from pytest_unordered import unordered

from strelka.scanners.scan_xml import ScanXml as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_xml(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """
    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "tags": unordered(["book", "author", "price", "year", "title"]),
        "tag_data": unordered(
            [
                {"tag": "category", "content": "{'category': 'science'}"},
                {"tag": "category", "content": "{'category': 'science'}"},
            ]
        ),
        "namespaces": unordered(["http://example.com/books"]),
        "total": {"tags": 5, "extracted": 0},
        "doc_type": '<!DOCTYPE bookstore SYSTEM "bookstore.dtd">',
        "version": "1.0",
        "emitted_content": [],
        "iocs": unordered(
            [
                {"ioc": "example.com", "ioc_type": "domain", "scanner": "ScanXml"},
                {"ioc": "www.w3.org", "ioc_type": "domain", "scanner": "ScanXml"},
            ]
        ),
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.xml",
        options={
            "extract_tags": ["Data"],
            "metadata_tags": ["category"],
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_xml_with_file(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """
    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "tags": unordered(
            [
                "encrypteddata",
                "canonicalizationmethod",
                "signaturemethod",
                "reference",
                "cipherdata",
                "embeddedfile",
                "signedinfo",
                "relationships",
                "ciphervalue",
                "encryptionmethod",
                "relationship",
                "data",
                "script",
                "digestvalue",
                "digestmethod",
            ]
        ),
        "tag_data": unordered(
            [
                {
                    "tag": "Type",
                    "content": "{'Id': 'rId1', 'Type': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/image', 'Target': '../media/image1.png'}",
                },
                {
                    "tag": "Type",
                    "content": "{'Id': 'rId3', 'Type': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/image', 'Target': '../media/image2.png'}",
                },
                {
                    "tag": "Type",
                    "content": "{'Id': 'rId2', 'Type': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink', 'Target': 'file:///\\\\\\\\\\\\\\\\127.0.0.1\\\\\\\\share\\\\\\\\EXCEL_OPEN_DOCUMENT.vbs', 'TargetMode': 'External'}",
                },
                {"tag": "Type", "content": "{'Id': 'file1', 'Type': 'image/png'}"},
                {
                    "tag": "Type",
                    "content": "{'Id': 'encData1', 'Type': 'http://www.w3.org/2001/04/xmlenc#Element'}",
                },
                {
                    "tag": "Type",
                    "content": "{'Id': 'rId4', 'Type': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink', 'Target': 'https://www.example.com', 'TargetMode': 'External'}",
                },
                {
                    "tag": "Type",
                    "content": "{'Id': 'rId5', 'Type': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink', 'Target': 'mailto:user@example.com', 'TargetMode': 'External'}",
                },
                {
                    "tag": "Type",
                    "content": "{'Id': 'rId6', 'Type': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink', 'Target': 'ftp://ftp.example.com/resource', 'TargetMode': 'External'}",
                },
            ]
        ),
        "namespaces": unordered(
            ["http://schemas.openxmlformats.org/package/2006/relationships"]
        ),
        "total": {"tags": 15, "extracted": 2},
        "doc_type": '<!DOCTYPE Relationships SYSTEM "relationships.dtd">',
        "version": "1.0",
        "emitted_content": unordered(
            [
                "function showAlert() {\n            alert('This is an embedded script within XML!');\n        }",
                "iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==",
            ]
        ),
        "iocs": unordered(
            [
                {"ioc": "127.0.0.1", "ioc_type": "ip", "scanner": "ScanXml"},
                {"ioc": "www.w3.org", "ioc_type": "domain", "scanner": "ScanXml"},
                {
                    "ioc": "schemas.openxmlformats.org",
                    "ioc_type": "domain",
                    "scanner": "ScanXml",
                },
                {"ioc": "ftp.example.com", "ioc_type": "domain", "scanner": "ScanXml"},
            ]
        ),
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_external.xml",
        options={
            "extract_tags": [
                "target",
                "script",
                "embeddedfile",
                "cipherdata",
                "data",
                "signedinfo",
                "encrypteddata",
            ],
            "metadata_tags": ["type"],
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
