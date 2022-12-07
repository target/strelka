import datetime
from strelka.scanners.scan_footer import ScanFooter


def test_scan_footer():
    """
    This tests the ScanFooter scanner.
    It attempts to validate the extraction of a string from a file's content.

    Pass: File is loaded, scanned, and footer value "mcee" is successfully extracted.
    Failure: Unable to load, scan, or extract value "mcee"
    """

    scanner = ScanFooter(
        {
            "name": "ScanFooter",
            "key": "scan_footer",
            "limits": {"scanner": 10},
        },
        "test_coordinate",
    )
    scanner.scan_wrapper(
        "foo bar mcee",
        {"uid": "12345", "name": "somename"},
        {"length": 4, "scanner_timeout": 5},
        datetime.date.today(),
    )
    assert scanner.event.get("footer") == "mcee"
