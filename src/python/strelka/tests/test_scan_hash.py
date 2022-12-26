from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_hash import ScanHash as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_hash(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "md5": "f58ebb5ce3e07a9dfc6dcca556b58291",
        "sha1": "67198a3ca72c49fb263f4a9749b4b79c50510155",
        "sha256": "f2f667e330da9f190eda77c74781963a0495c3953a653747fe475b99421efdda",
        "ssdeep": "48:6XZmqLorrAtzkuPS/6NMn3BCiLMjOiuCOlXTuZKFWpfbNtm:GmbWl8xCYDlTunzNt",
        "tlsh": "T1D281701183EA87B6E9334732BDB363804279FB41DCAB4B6F2884530B2D163544DA3F61",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.exe",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
