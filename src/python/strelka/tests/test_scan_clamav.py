import logging
import subprocess
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_clamav import ScanClamav as ScanUnderTest
from strelka.tests import run_test_scan


def retrieve_signatures():
    """
    Utility function that will retrieve the ClamAV signature DB when called. Currently this is set up to run
    when initializing the ClamAV scanner test. Should take around 10-15 seconds to retrieve the signatures from the remote DB.
    """
    logging.info("Retrieving ClamAV signatures via freshclam.")
    try:
        # Run freshclam to get the newest database signature
        with subprocess.Popen(
            ["freshclam"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as proc:
            stdout, stderr = proc.communicate()

        logging.info(stdout)

    except Exception as e:
        error_msg = f"Failed to download clam signatures: {e}"
        logging.error(error_msg)


def test_scan_clamav(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """
    retrieve_signatures()
    test_scan_event = {
        "Data read": "526.71 KiB (ratio 1.06",
        "Data scanned": "557.96 KiB",
        "End Date": mock.ANY,
        "Engine version": mock.ANY,
        "Infected files": "0",
        "Known viruses": mock.ANY,
        "Scanned directories": "0",
        "Scanned files": "1",
        "Start Date": mock.ANY,
        "Time": mock.ANY,
        "elapsed": mock.ANY,
        "flags": [],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.png",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
