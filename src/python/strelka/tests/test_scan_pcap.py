from pathlib import Path
from unittest import TestCase, mock

from pytest_unordered import unordered
from strelka.scanners.scan_pcap import ScanPcap as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_pcap(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 3, "extracted": 3},
        "files": [
            {
                "ts": 1673576655.41892,
                "fuid": "FOxTJwn9u5H1hBXn1",
                "tx_hosts": ["192.168.174.131"],
                "rx_hosts": ["192.168.174.1"],
                "conn_uids": mock.ANY,
                "source": "HTTP",
                "depth": 0,
                "analyzers": unordered(["PE", "EXTRACT"]),
                "mime_type": "application/x-dosexec",
                "duration": 0.00018906593322753906,
                "is_orig": False,
                "seen_bytes": 4096,
                "total_bytes": 4096,
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "timedout": False,
                "extracted": "extract-1673576655.41892-HTTP-FOxTJwn9u5H1hBXn1",
                "extracted_cutoff": False,
            },
            {
                "ts": 1673576666.163778,
                "fuid": "FxYAi61ktBsEM4hpNd",
                "tx_hosts": ["192.168.174.131"],
                "rx_hosts": ["192.168.174.1"],
                "conn_uids": mock.ANY,
                "source": "HTTP",
                "depth": 0,
                "analyzers": unordered(["EXTRACT"]),
                "mime_type": "image/jpeg",
                "duration": 0.007551908493041992,
                "is_orig": False,
                "seen_bytes": 308566,
                "total_bytes": 308566,
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "timedout": False,
                "extracted": "extract-1673576666.163778-HTTP-FxYAi61ktBsEM4hpNd",
                "extracted_cutoff": False,
            },
            {
                "ts": 1673576677.801391,
                "fuid": "FoNGFk1uRR9pVo9XKi",
                "tx_hosts": ["192.168.174.131"],
                "rx_hosts": ["192.168.174.1"],
                "conn_uids": mock.ANY,
                "source": "HTTP",
                "depth": 0,
                "analyzers": unordered(["EXTRACT"]),
                "mime_type": "application/xml",
                "duration": 0.0,
                "is_orig": False,
                "seen_bytes": 620,
                "total_bytes": 620,
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "timedout": False,
                "extracted": "extract-1673576677.801391-HTTP-FoNGFk1uRR9pVo9XKi",
                "extracted_cutoff": False,
            },
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pcap",
        options={"scanner_timeout": 20},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_pcap_ng(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 3, "extracted": 3},
        "files": [
            {
                "ts": 1673576655.41892,
                "fuid": "FOxTJwn9u5H1hBXn1",
                "tx_hosts": ["192.168.174.131"],
                "rx_hosts": ["192.168.174.1"],
                "conn_uids": mock.ANY,
                "source": "HTTP",
                "depth": 0,
                "analyzers": unordered(["PE", "EXTRACT"]),
                "mime_type": "application/x-dosexec",
                "duration": 0.00018906593322753906,
                "is_orig": False,
                "seen_bytes": 4096,
                "total_bytes": 4096,
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "timedout": False,
                "extracted": "extract-1673576655.41892-HTTP-FOxTJwn9u5H1hBXn1",
                "extracted_cutoff": False,
            },
            {
                "ts": 1673576666.163778,
                "fuid": "FxYAi61ktBsEM4hpNd",
                "tx_hosts": ["192.168.174.131"],
                "rx_hosts": ["192.168.174.1"],
                "conn_uids": mock.ANY,
                "source": "HTTP",
                "depth": 0,
                "analyzers": unordered(["EXTRACT"]),
                "mime_type": "image/jpeg",
                "duration": 0.007551908493041992,
                "is_orig": False,
                "seen_bytes": 308566,
                "total_bytes": 308566,
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "timedout": False,
                "extracted": "extract-1673576666.163778-HTTP-FxYAi61ktBsEM4hpNd",
                "extracted_cutoff": False,
            },
            {
                "ts": 1673576677.801391,
                "fuid": "FoNGFk1uRR9pVo9XKi",
                "tx_hosts": ["192.168.174.131"],
                "rx_hosts": ["192.168.174.1"],
                "conn_uids": mock.ANY,
                "source": "HTTP",
                "depth": 0,
                "analyzers": unordered(["EXTRACT"]),
                "mime_type": "application/xml",
                "duration": 0.0,
                "is_orig": False,
                "seen_bytes": 620,
                "total_bytes": 620,
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "timedout": False,
                "extracted": "extract-1673576677.801391-HTTP-FoNGFk1uRR9pVo9XKi",
                "extracted_cutoff": False,
            },
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pcapng",
        options={"scanner_timeout": 20},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
