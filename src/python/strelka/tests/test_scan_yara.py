from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_yara import ScanYara as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_yara(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "hex": [],
        "matches": ["test", "hex_extraction_test", "meta_test"],
        "meta": mock.ANY,
        "rules_loaded": 3,
        "tags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=str(Path(__file__).parent / "fixtures/test.txt"),
        options={
            "location": str(Path(__file__).parent / "fixtures/test.yara"),
            "compiled": {
                "enabled": False,
                "filename": "rules.compiled",
            },
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_bad_yara(mocker):
    """
    This test was implemented to test a more complex and unsupported rule. A bug was observed that was
    not triggered by the basic YARA test.
    Src: https://github.com/target/strelka/issues/410
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [
            'compiling_error_syntax_/strelka/strelka/tests/fixtures/test_elk_linux_torte.yara(31): undefined identifier "is__elf"',
            "no_rules_loaded",
        ],
        "hex": [],
        "matches": [],
        "meta": mock.ANY,
        "rules_loaded": 0,
        "tags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=str(Path(__file__).parent / "fixtures/test.txt"),
        options={
            "location": str(Path(__file__).parent / "fixtures/"),
            "compiled": {
                "enabled": False,
                "filename": "rules.compiled",
            },
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_yara_hex_extraction(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """
    matched_hex = {
        "dump": [
            "000002ff  74 20 6d 69 20 70 72 6f 69 6e 20 73 65 64 2e 20  t mi proin sed. ",
            "0000030f  56 65 6e 65 6e 61 74 69 73 20 74 65 6c 6c 75 73  Venenatis tellus",
            "0000031f  20 69 6e 20 6d 65 74 75 73 20 76 75 6c 70 75 74   in metus vulput",
            "0000032f  61 74 65 2e 20 44 69 63 74 75 6d 73 74 20 76 65  ate. Dictumst ve",
            "0000033f  73 74 69 62 75 6c 75 6d 20 72 68 6f 6e 63 75 73  stibulum rhoncus",
        ],
        "rule": "hex_extraction_test",
    }

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "hex": [matched_hex],
        "matches": ["test", "hex_extraction_test", "meta_test"],
        "meta": [],
        "rules_loaded": 3,
        "tags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=str(Path(__file__).parent / "fixtures/test.txt"),
        options={
            "location": str(Path(__file__).parent / "fixtures/test.yara"),
            "show_all_meta": False,
            "store_offset": True,
            "offset_meta_key": "StrelkaHexDump",
            "offset_padding": 32,
            "compiled": {
                "enabled": False,
                "filename": "rules.compiled",
            },
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_yara_meta(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "collection": [],
        "detection": [
            {
                "name": "meta_test",
                "ruleset": "default",
                "author": "John Doe",
            },
        ],
        "elapsed": mock.ANY,
        "flags": [],
        "hex": [],
        "information": [],
        "matches": ["test", "hex_extraction_test", "meta_test"],
        "meta": [
            {
                "identifier": "StrelkaHexDump",
                "rule": "hex_extraction_test",
                "value": True,
            },
            {
                "identifier": "author",
                "rule": "meta_test",
                "value": "John Doe",
            },
            {
                "identifier": "scope",
                "rule": "meta_test",
                "value": "detection",
            },
        ],
        "rules_loaded": 3,
        "tags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=str(Path(__file__).parent / "fixtures/test.txt"),
        options={
            "location": str(Path(__file__).parent / "fixtures/test.yara"),
            "category_key": "scope",
            "categories": {
                "collection": {},
                "detection": {
                    "show_meta": True,
                },
                "information": {},
            },
            "meta_fields": {
                "name": "",
                "ruleset": "",
                "author": "",
            },
            "show_all_meta": True,
            "compiled": {
                "enabled": False,
                "filename": "rules.compiled",
            },
        },
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
