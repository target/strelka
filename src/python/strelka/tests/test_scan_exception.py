from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_exception import ScanException as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_exception(mocker):
    """
    Pass: Sample event matches output of scanner. Exception should be caught by scan_wrapper() and a flag set.
    Failure: Unable to load file or sample event fails to match, meaning the exception was uncaught.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": ["uncaught_exception"],
        "exception": "Traceback (most recent call last):\n\n  File \"/home/karl/strelka/src/python/strelka/strelka.py\", line 173, in scan_wrapper\n    self.scan(data, file, options, expire_at)\n\n  File \"/home/karl/strelka/src/python/strelka/scanners/scan_exception.py\", line 23, in scan\n    raise Exception(\"Scanner Exception\")\n\nException: Scanner Exception\n",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.empty",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
