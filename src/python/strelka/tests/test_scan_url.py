import pytest
import datetime
from strelka.scanners.scan_url import ScanUrl

scanner = ScanUrl(
        {"name": "ScanUrl", "key": "scan_url", "limits": {"scanner": 10}},
        "test_coordinate",
    )

tests = [
    (b"some othervalue foo", []),
    (b"http://foobar.test.com", [b"http://foobar.test.com"]),
    (b"foo http://foobar.test.com bar", [b"http://foobar.test.com"]),
    (b"http://\n", []),
    (b"noschema.foo\n", [b"noschema.foo"]),
    ]

@pytest.mark.parametrize("data,expected", tests)
def test_scan_simple_url(data, expected):
    """Extract URLs from payloads"""

    scanner.scan_wrapper(
        data,
        "somefile.foo",
        {"length": 4, "scanner_timeout": 5},
        datetime.date.today(),
    )
    assert scanner.event.get("urls") == expected
