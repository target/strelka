import datetime
from pathlib import Path
from strelka.scanners.scan_gif import ScanGif


def test_scan_gif(mocker):
    """
    This tests the ScanGif scanner.
    It attempts to validate a given GIFs "trailer index" value.

    Pass: Trailer index matches specified value.
    Failure: Unable to load file or trailer index does not match specified value.
    """

    scanner = ScanGif(
        {
            "name": "ScanGif",
            "key": "scan_gif",
            "limits": {"scanner": 10}
        },
        "test_coordinate",
    )

    mocker.patch.object(ScanGif, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test.gif").read_bytes(),
        {
            "uid": "12345",
            "name": "somename"
        },
        {
            "scanner_timeout": 5
        },
        datetime.date.today(),
    )
    assert scanner.event.get("trailer_index") == 3806
