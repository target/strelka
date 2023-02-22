import os
from pathlib import Path

import yaml

from strelka import strelka


def test_scanner_import() -> None:
    """
    Pass: All test fixtures match the given yara and mime matches.
    Failure: At least one test fixture does not match the given yara and mime matches.
    """

    if os.path.exists("/etc/strelka/backend.yaml"):
        backend_cfg_path: str = "/etc/strelka/backend.yaml"
    else:
        backend_cfg_path: str = Path(
            Path(__file__).parent / "../../../../configs/python/backend/backend.yaml"
        )

    with open(backend_cfg_path, "r") as f:
        backend_cfg = yaml.safe_load(f.read())

        backend = strelka.Backend(backend_cfg, disable_coordinator=True)

        backend.check_scanners()
