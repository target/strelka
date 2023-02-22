import os
import time
import uuid
from pathlib import Path
from unittest import TestCase, mock

import yaml

from strelka import strelka


def test_distribute(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    expected = [
        {
            "file": {
                "depth": 0,
                "flavors": {"mime": ["text/html"], "yara": ["html_file"]},
                "name": "",
                "scanners": [
                    "ScanEntropy",
                    "ScanFooter",
                    "ScanHash",
                    "ScanHeader",
                    "ScanHtml",
                    "ScanTlsh",
                    "ScanYara",
                ],
                "size": 5875,
                "source": "",
                "tree": {
                    "node": mock.ANY,
                    "parent": "",
                    "root": mock.ANY,
                },
            },
            "scan": {
                "entropy": mock.ANY,
                "footer": mock.ANY,
                "hash": mock.ANY,
                "header": mock.ANY,
                "html": mock.ANY,
                "tlsh": mock.ANY,
                "yara": mock.ANY,
            },
        },
        {
            "file": {
                "depth": 1,
                "flavors": {
                    "external": ["", ""],
                    "mime": ["text/plain"],
                    "yara": ["javascript_file"],
                },
                "name": "script_1",
                "scanners": [
                    "ScanEntropy",
                    "ScanFooter",
                    "ScanHash",
                    "ScanHeader",
                    "ScanJavascript",
                    "ScanTlsh",
                    "ScanYara",
                ],
                "size": 221,
                "source": "ScanHtml",
                "tree": {
                    "node": mock.ANY,
                    "parent": mock.ANY,
                    "root": mock.ANY,
                },
            },
            "scan": {
                "entropy": mock.ANY,
                "footer": mock.ANY,
                "hash": mock.ANY,
                "header": mock.ANY,
                "javascript": mock.ANY,
                "tlsh": mock.ANY,
                "yara": {
                    "elapsed": mock.ANY,
                    "flags": [],
                    "matches": ["test"],
                    "tags": [],
                    "meta": [],
                },
            },
        },
    ]

    if os.path.exists("/etc/strelka/backend.yaml"):
        backend_cfg_path: str = "/etc/strelka/backend.yaml"
    else:
        backend_cfg_path: str = Path(
            Path(__file__).parent / "../../../../configs/python/backend/backend.yaml"
        )

    with open(backend_cfg_path, "r") as f:
        backend_cfg = yaml.safe_load(f.read())

        backend = strelka.Backend(backend_cfg, disable_coordinator=True)

        with open(
            Path(Path(__file__).parent / "../tests/fixtures/test.html"), "rb"
        ) as test_file:
            data = test_file.read()
            file = strelka.File(data=data)

            events = backend.distribute(str(uuid.uuid4()), file, int(time.time()) + 300)

            TestCase.maxDiff = None
            TestCase().assertListEqual(expected, events)


def test_distribute_spaces(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    expected = [
        {
            "file": {
                "depth": 0,
                "flavors": {"mime": ["text/html"], "yara": ["html_file"]},
                "name": "",
                "scanners": [
                    "ScanEntropy",
                    "ScanFooter",
                    "ScanHash",
                    "ScanHeader",
                    "ScanHtml",
                    "ScanTlsh",
                    "ScanYara",
                ],
                "size": 5880,
                "source": "",
                "tree": {
                    "node": mock.ANY,
                    "parent": "",
                    "root": mock.ANY,
                },
            },
            "scan": {
                "entropy": mock.ANY,
                "footer": mock.ANY,
                "hash": mock.ANY,
                "header": mock.ANY,
                "html": mock.ANY,
                "tlsh": mock.ANY,
                "yara": mock.ANY,
            },
        },
        {
            "file": {
                "depth": 1,
                "flavors": {
                    "external": ["", ""],
                    "mime": ["text/plain"],
                    "yara": ["javascript_file"],
                },
                "name": "script_1",
                "scanners": [
                    "ScanEntropy",
                    "ScanFooter",
                    "ScanHash",
                    "ScanHeader",
                    "ScanJavascript",
                    "ScanTlsh",
                    "ScanYara",
                ],
                "size": 221,
                "source": "ScanHtml",
                "tree": {
                    "node": mock.ANY,
                    "parent": mock.ANY,
                    "root": mock.ANY,
                },
            },
            "scan": {
                "entropy": mock.ANY,
                "footer": mock.ANY,
                "hash": mock.ANY,
                "header": mock.ANY,
                "javascript": mock.ANY,
                "tlsh": mock.ANY,
                "yara": {
                    "elapsed": mock.ANY,
                    "flags": [],
                    "matches": ["test"],
                    "tags": [],
                    "meta": [],
                },
            },
        },
    ]

    if os.path.exists("/etc/strelka/backend.yaml"):
        backend_cfg_path: str = "/etc/strelka/backend.yaml"
    else:
        backend_cfg_path: str = Path(
            Path(__file__).parent / "../../../../configs/python/backend/backend.yaml"
        )

    with open(backend_cfg_path, "r") as f:
        backend_cfg = yaml.safe_load(f.read())

        backend = strelka.Backend(backend_cfg, disable_coordinator=True)

        with open(
            Path(Path(__file__).parent / "../tests/fixtures/test_whitespace.html"), "rb"
        ) as test_file:
            data = test_file.read()
            file = strelka.File(data=data)

            events = backend.distribute(str(uuid.uuid4()), file, int(time.time()) + 300)

            TestCase.maxDiff = None
            TestCase().assertListEqual(expected, events)
