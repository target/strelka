import gzip
from base64 import b64encode
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_save import ScanSave as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_save(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    # Test file path
    fixture_path = Path(__file__).parent / "fixtures/test.yaml"

    # Compress and encode file contents for comparison
    with open(fixture_path, "rb") as f:
        file_contents = b64encode(gzip.compress(f.read()))

    test_scan_event = {
        "elapsed": mock.ANY,
        "file": file_contents,
        "compression": {"enabled": True, "algorithm": "gzip"},
        "encoding": "base64",
        "flags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=fixture_path,
    )

    # gzip compression will produce slightly different output for each run
    TestCase.maxDiff = 4
    TestCase().assertDictEqual(test_scan_event, scanner_event)

