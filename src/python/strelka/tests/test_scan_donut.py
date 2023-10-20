from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_donut import ScanDonut as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_donut(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"donuts": 1, "files": 1},
        "donuts": [
            {
                "compression_type": "DONUT_COMPRESS_NONE",
                "decoy_module": "",
                "entropy_type": "DONUT_ENTROPY_DEFAULT",
                "instance_type": "DONUT_INSTANCE_EMBED",
                "module_type": "DONUT_MODULE_NET_DLL",
                "instance_version": "1.0",
                "loader_version": "1.0_64",
                "offset_loader_start": 10196,
                "offsets": {"size_instance": 4744, "encryption_start": 572},
            }
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_donut.bin",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_donut_compressed(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"donuts": 1, "files": 1},
        "donuts": [
            {
                "compression_type": "DONUT_COMPRESS_APLIB",
                "decoy_module": "",
                "entropy_type": "DONUT_ENTROPY_DEFAULT",
                "instance_type": "DONUT_INSTANCE_EMBED",
                "module_type": "DONUT_MODULE_NET_DLL",
                "instance_version": "1.0",
                "loader_version": "1.0_64",
                "offset_loader_start": 7913,
                "offsets": {"size_instance": 4744, "encryption_start": 572},
            }
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_donut_compressed.bin",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
