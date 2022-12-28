from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_xml import ScanXml as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_xml(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "namespaces": [None],
        "tag_data": [],
        "flags": [],
        "tags": [
            "package",
            "name",
            "version",
            "description",
            "maintainer",
            "license",
            "buildtool_depend",
            "depend",
            "build_depend",
            "exec_depend",
            "export",
            "nodelet",
        ],
        "total": {"extracted": 0, "tags": 15},
        "version": "1.0",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.xml",
    )
    print(scanner_event)
    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
