from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_iqy import ScanIqy as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_iqy(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "address_found": True,
        "iocs": [
            {
                "ioc": "github.com",
                "ioc_type": "domain",
                "scanner": "ScanIqy",
            },
            {
                "ioc": "https://github.com/target/strelka/blob/master/docs/index.html",
                "ioc_type": "url",
                "scanner": "ScanIqy",
            },
        ],
    }
    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.iqy",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
