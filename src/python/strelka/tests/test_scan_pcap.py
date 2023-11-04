from pathlib import Path
from unittest import TestCase, mock

from pytest_unordered import unordered

from strelka.scanners.scan_pcap import ScanPcap as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_pcap(mocker):
    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 3, "extracted": 3},
        "files": [
            {
                "analyzers": unordered(["PE", "EXTRACT"]),
                "depth": 0,
                "duration": 0.00018906593322753906,
                "extracted": "extract-1673576655.41892-HTTP-FOxTJwn9u5H1hBXn1",
                "extracted_cutoff": False,
                "fuid": "FOxTJwn9u5H1hBXn1",
                "id.orig_h": "192.168.174.1",
                "id.orig_p": 13147,
                "id.resp_h": "192.168.174.131",
                "id.resp_p": 8080,
                "is_orig": False,
                "local_orig": True,
                "mime_type": "application/x-dosexec",
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "seen_bytes": 4096,
                "source": "HTTP",
                "timedout": False,
                "total_bytes": 4096,
                "ts": 1673576655.41892,
                "uid": mock.ANY,
            },
            {
                "analyzers": unordered(["EXTRACT"]),
                "depth": 0,
                "duration": 0.007551908493041992,
                "extracted": "extract-1673576666.163778-HTTP-FxYAi61ktBsEM4hpNd",
                "extracted_cutoff": False,
                "fuid": "FxYAi61ktBsEM4hpNd",
                "id.orig_h": "192.168.174.1",
                "id.orig_p": 13162,
                "id.resp_h": "192.168.174.131",
                "id.resp_p": 8080,
                "is_orig": False,
                "local_orig": True,
                "mime_type": "image/jpeg",
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "seen_bytes": 308566,
                "source": "HTTP",
                "timedout": False,
                "total_bytes": 308566,
                "ts": 1673576666.163778,
                "uid": mock.ANY,
            },
            {
                "analyzers": unordered(["EXTRACT"]),
                "depth": 0,
                "duration": 0.0,
                "extracted": "extract-1673576677.801391-HTTP-FoNGFk1uRR9pVo9XKi",
                "extracted_cutoff": False,
                "fuid": "FoNGFk1uRR9pVo9XKi",
                "id.orig_h": "192.168.174.1",
                "id.orig_p": 13176,
                "id.resp_h": "192.168.174.131",
                "id.resp_p": 8080,
                "is_orig": False,
                "local_orig": True,
                "mime_type": "application/xml",
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "seen_bytes": 620,
                "source": "HTTP",
                "timedout": False,
                "total_bytes": 620,
                "ts": 1673576677.801391,
                "uid": mock.ANY,
            }
        ]
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
                "analyzers": unordered(["PE", "EXTRACT"]),
                "depth": 0,
                "duration": mock.ANY,
                "extracted": mock.ANY,
                "extracted_cutoff": False,
                "fuid": "FOxTJwn9u5H1hBXn1",
                "id.orig_h": "192.168.174.1",
                "id.orig_p": 13147,
                "id.resp_h": "192.168.174.131",
                "id.resp_p": 8080,
                "is_orig": False,
                "local_orig": True,
                "mime_type": "application/x-dosexec",
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "seen_bytes": 4096,
                "source": "HTTP",
                "timedout": False,
                "total_bytes": 4096,
                "ts": 1673576655.41892,
                "uid": mock.ANY
            },
            {
                "analyzers": unordered(["EXTRACT"]),
                "depth": 0,
                "duration": mock.ANY,
                "extracted": mock.ANY,
                "extracted_cutoff": False,
                "fuid": "FxYAi61ktBsEM4hpNd",
                "id.orig_h": "192.168.174.1",
                "id.orig_p": 13162,
                "id.resp_h": "192.168.174.131",
                "id.resp_p": 8080,
                "is_orig": False,
                "local_orig": True,
                "mime_type": "image/jpeg",
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "seen_bytes": 308566,
                "source": "HTTP",
                "timedout": False,
                "total_bytes": 308566,
                "ts": 1673576666.163778,
                "uid": mock.ANY
            },
            {
                "analyzers": unordered(["EXTRACT"]),
                "depth": 0,
                "duration": mock.ANY,
                "extracted": mock.ANY,
                "extracted_cutoff": False,
                "fuid": "FoNGFk1uRR9pVo9XKi",
                "id.orig_h": "192.168.174.1",
                "id.orig_p": 13176,
                "id.resp_h": "192.168.174.131",
                "id.resp_p": 8080,
                "is_orig": False,
                "local_orig": True,
                "mime_type": "application/xml",
                "missing_bytes": 0,
                "overflow_bytes": 0,
                "seen_bytes": 620,
                "source": "HTTP",
                "timedout": False,
                "total_bytes": 620,
                "ts": 1673576677.801391,
                "uid": mock.ANY
            }
        ]
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pcapng",
        options={"scanner_timeout": 20},
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)
