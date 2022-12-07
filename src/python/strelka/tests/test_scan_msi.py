import datetime
from pathlib import Path
from strelka.scanners.scan_msi import ScanMsi


def test_scan_msi(mocker):
    """
    This tests the ScanGif scanner.
    It attempts to validate a given GIFs "trailer index" value.

    Pass: Trailer index matches specified value.
    Failure: Unable to load file or trailer index does not match specified value.
    """

    scanner = ScanMsi(
        {
            "name": "ScanMsi",
            "key": "scan_msi",
            "limits": {"scanner": 10}
        },
        "test_coordinate",
    )

    mocker.patch.object(ScanMsi, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test.msi").read_bytes(),
        {
            "uid": "12345",
            "name": "somename"
        },
        {
            "scanner_timeout": 5
        },
        datetime.date.today(),
    )

    assert scanner.event.get("Software") == "InstallShield® X - Professional Edition 10.0"
    assert scanner.event.get("Keywords") == "Installer,MSI,Database"
    assert scanner.event.get("Author") == "Microsoft Corporation"
