from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_pyinstaller import ScanPyinstaller as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_pyinstaller(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "cookie": {
            "archive_length": 1381481,
            "magic": "MEI\f\u000b\n\u000b\u000e",
            "pylib_name": "Python",
            "pyvers": 313,
            "toc_length": 400,
            "toc_offset": 1380993,
        },
        "pkg_item_binary": [],
        "pkg_item_data": [],
        "pkg_item_dependency": [],
        "pkg_item_pymodule": [
            {
                "compression_flag": 1,
                "data_length": 235,
                "entry_offset": 0,
                "name": "struct",
                "typecode": "m",
                "uncompressed_length": 289,
            },
            {
                "compression_flag": 1,
                "data_length": 2754,
                "entry_offset": 235,
                "name": "pyimod01_archive",
                "typecode": "m",
                "uncompressed_length": 4797,
            },
            {
                "compression_flag": 1,
                "data_length": 13646,
                "entry_offset": 2989,
                "name": "pyimod02_importers",
                "typecode": "m",
                "uncompressed_length": 31830,
            },
            {
                "compression_flag": 1,
                "data_length": 2820,
                "entry_offset": 16635,
                "name": "pyimod03_ctypes",
                "typecode": "m",
                "uncompressed_length": 6453,
            },
        ],
        "pkg_item_pypackage": [],
        "pkg_item_pysource": [
            {
                "compression_flag": 1,
                "data_length": 1040,
                "entry_offset": 19455,
                "name": "pyiboot01_bootstrap",
                "typecode": "s",
                "uncompressed_length": 1900,
            },
            {
                "compression_flag": 1,
                "data_length": 1532,
                "entry_offset": 20495,
                "name": "pyi_rth_inspect",
                "typecode": "s",
                "uncompressed_length": 2831,
            },
            {
                "compression_flag": 1,
                "data_length": 112,
                "entry_offset": 22027,
                "name": "hello_world",
                "typecode": "s",
                "uncompressed_length": 137,
            },
        ],
        "pkg_item_pyz": [
            {
                "compression_flag": 0,
                "data_length": 1358854,
                "entry_offset": 22139,
                "name": "PYZ-00.pyz",
                "typecode": "z",
                "uncompressed_length": 1358854,
            }
        ],
        "pkg_item_runtime_option": [],
        "pkg_item_splash": [],
        "pkg_item_zipfile": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_pyinstaller",
        options={"location": str(Path(Path(__file__).parent / "fixtures/test.yaml"))},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
