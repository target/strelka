import datetime
from pathlib import Path


def run_test_scan(
    mocker,
    scan_class,
    fixture_path,
    options=None,
    backend_cfg=None,
    coordinator="test_coordinate"
):
    if options is None:
        options = {}
    if "scanner_timeout" not in options:
        options["scanner_timeout"] = 10
    if backend_cfg is None:
        backend_cfg = {"limits": {"scanner": 10}}

    scanner = scan_class(backend_cfg, coordinator)

    mocker.patch.object(scanner.__class__, "upload_to_coordinator", return_value=None)

    scanner.scan_wrapper(
        data=Path(fixture_path).read_bytes(),
        file={"uid": "12345", "name": "test"},
        options=options,
        expire_at=datetime.date.today(),
    )

    return scanner.event
