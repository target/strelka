from pathlib import Path
from unittest import TestCase, mock

import pytest

from strelka.scanners.scan_transcode import ScanTranscode as ScanUnderTest
from strelka.tests import run_test_scan

output_formats = ["gif", "webp", "jpeg", "bmp", "png", "tiff"]


@pytest.mark.parametrize("output_format", output_formats)
def test_scan_transcode_avif(mocker, output_format) -> None:
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {"elapsed": mock.ANY, "flags": ["transcoded"]}

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_qr.avif",
        options={"output_format": output_format},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


@pytest.mark.parametrize("output_format", output_formats)
def test_scan_transcode_heic(mocker, output_format) -> None:
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {"elapsed": mock.ANY, "flags": ["transcoded"]}

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_qr.heic",
        options={"output_format": output_format},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


@pytest.mark.parametrize("output_format", output_formats)
def test_scan_transcode_heif(mocker, output_format) -> None:
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {"elapsed": mock.ANY, "flags": ["transcoded"]}

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_qr.heif",
        options={"output_format": output_format},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_transcode_broken_heic(mocker) -> None:
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {"elapsed": mock.ANY, "flags": ["unidentified_image"]}

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_broken.heic",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
