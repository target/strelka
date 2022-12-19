import datetime
from pathlib import Path


def run_test_scan(mocker, scan_class, fixture_path, backend_cfg=None, coordinator="test_coordinate", scanner_timeout=5):
    if backend_cfg is None:
        backend_cfg = {"limits": {"scanner": 10}}
    scanner = scan_class(backend_cfg, coordinator)

    mocker.patch.object(scanner.__class__, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(fixture_path).read_bytes(),
        {"uid": "12345", "name": "test"},
        {"scanner_timeout": scanner_timeout},
        datetime.date.today(),
    )

    return scanner.event
