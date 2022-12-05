import datetime
from strelka.scanners.scan_footer import ScanFooter


def test_scan_footer():
    """Attach file footer"""

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
