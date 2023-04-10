import bz2
import gzip
import lzma
from base64 import b64encode, b85encode
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_save import ScanSave as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_save_b64_gzip(mocker):
    """
    Test gzip compression and base64 encoding
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    # Test parameters
    compression = "gzip"
    encoding = "base64"
    fixture_path = Path(__file__).parent / "fixtures/test.txt"

    # Compress and encode file contents for comparison
    with open(fixture_path, "rb") as f:
        file_contents = b64encode(gzip.compress(f.read()))

    test_scan_event = {
        "elapsed": mock.ANY,
        "file": file_contents,
        "compression": compression,
        "encoding": encoding,
        "flags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=fixture_path,
        options={"compression": compression, "encoding": encoding},
    )

    # gzip compression will produce slightly different output for each run
    TestCase.maxDiff = 4
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_save_b64_bzip2(mocker):
    """
    Test bzip2 compression and base64 encoding
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    # Test parameters
    compression = "bzip2"
    encoding = "base64"
    fixture_path = Path(__file__).parent / "fixtures/test.txt"

    # Compress and encode file contents for comparison
    with open(fixture_path, "rb") as f:
        file_contents = b64encode(bz2.compress(f.read()))

    test_scan_event = {
        "elapsed": mock.ANY,
        "file": file_contents,
        "compression": compression,
        "encoding": encoding,
        "flags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=fixture_path,
        options={"compression": compression, "encoding": encoding},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_save_b85_lzma(mocker):
    """
    Test lzma compression and base85 encoding
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    # Test parameters
    compression = "lzma"
    encoding = "base85"
    fixture_path = Path(__file__).parent / "fixtures/test.txt"

    # Compress and encode file contents for comparison
    with open(fixture_path, "rb") as f:
        file_contents = b85encode(lzma.compress(f.read()))

    test_scan_event = {
        "elapsed": mock.ANY,
        "file": file_contents,
        "compression": compression,
        "encoding": encoding,
        "flags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=fixture_path,
        options={"compression": compression, "encoding": encoding},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_save_b64_none(mocker):
    """
    Test no compression and base64 encoding
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    # Test parameters
    compression = "none"
    encoding = "base64"
    fixture_path = Path(__file__).parent / "fixtures/test.txt"

    # Encode file contents for comparison
    with open(fixture_path, "rb") as f:
        file_contents = b64encode(f.read())

    test_scan_event = {
        "elapsed": mock.ANY,
        "file": file_contents,
        "compression": compression,
        "encoding": encoding,
        "flags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=fixture_path,
        options={"compression": compression, "encoding": encoding},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
