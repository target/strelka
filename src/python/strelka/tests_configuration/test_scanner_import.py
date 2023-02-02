import os
from pathlib import Path

import redis
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

        coordinator = redis.StrictRedis(host="127.0.0.1", port=65535, db=0)

        backend = strelka.Backend(backend_cfg, coordinator)

        backend.check_scanners()
