from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_tlsh import ScanTlsh as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_tlsh(mocker):
    """
    This test matches on multiple TLSH hashes in `test.yaml`.
    This test should end up with the correct answer, a score of 0, rather than a score 9, which it will match on first.
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """
    test_scan_event = {
        "elapsed": mock.ANY,
        "match": {
            "family": "TestMatchA",
            "score": 0,
            "tlsh": "T120957D477C8041A6C0AA9336896652D17B30BC991F2127D32F60F7F92F367E85E7931A",
        },
        "flags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.tlsh",
        options={"location": str(Path(Path(__file__).parent / "fixtures/test.yaml"))},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
