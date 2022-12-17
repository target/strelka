import datetime
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_zip import ScanZip


def test_scan_zip(mocker):
    """
    This tests the ScanZip scanner with a ZIP file.

    Pass: Sample event matches output of ScanZip.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_zip_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "total": {"files": 4, "extracted": 4},
        "files": [
            {
                "file_name": "hidden/lorem-hidden.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
            },
            {
                "file_name": "hidden/lorem-readonly.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
            },
            {
                "file_name": "hidden/lorem.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
            },
            {
                "file_name": "lorem.txt",
                "file_size": 4015,
                "compression_size": 1425,
                "compression_rate": 64.51,
            },
        ],
        "compression_rate": 64.51,
    }

    scanner = ScanZip(
        {"name": "ScanZip", "key": "scan_zip", "limits": {"scanner": 10}},
        "test_coordinate",
    )

    mocker.patch.object(ScanZip, "upload_to_coordinator", return_value=None)
    scanner.scan_wrapper(
        Path(Path(__file__).parent / "fixtures/test.zip").read_bytes(),
        {"uid": "12345", "name": "somename"},
        {"scanner_timeout": 5},
        datetime.date.today(),
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_zip_event, scanner.event)


# def test_scan_zip_zip_password(mocker):
#     """
#     This tests the ScanZip scanner with a ZipCrypto protecte ZIP file, password "password", which is in passwords.dat.
#
#     Pass: Sample event matches output of ScanZip.
#     Failure: Unable to load file or sample event fails to match.
#     """
#
#     test_scan_zip_zip_password_event = {
#         "elapsed": mock.ANY,
#         "flags": ["encrypted"],
#         "password": "password",
#         "total": {"files": 4, "extracted": 4},
#         "files": [
#             {
#                 "file_name": "hidden/lorem-hidden.txt",
#                 "file_size": 4015,
#                 "compression_size": 1437,
#                 "compression_rate": 64.21,
#             },
#             {
#                 "file_name": "hidden/lorem-readonly.txt",
#                 "file_size": 4015,
#                 "compression_size": 1437,
#                 "compression_rate": 64.21,
#             },
#             {
#                 "file_name": "hidden/lorem.txt",
#                 "file_size": 4015,
#                 "compression_size": 1437,
#                 "compression_rate": 64.21,
#             },
#             {
#                 "file_name": "lorem.txt",
#                 "file_size": 4015,
#                 "compression_size": 1437,
#                 "compression_rate": 64.21,
#             },
#         ],
#         "compression_rate": 64.21,
#     }
#
#     scanner = ScanZip(
#         {"name": "ScanZip", "key": "scan_zip", "limits": {"scanner": 10}},
#         "test_coordinate",
#     )
#
#     mocker.patch.object(ScanZip, "upload_to_coordinator", return_value=None)
#     scanner.scan_wrapper(
#         Path(Path(__file__).parent / "fixtures/test_zip_password.zip").read_bytes(),
#         {"uid": "12345", "name": "somename"},
#         {"scanner_timeout": 5},
#         datetime.date.today(),
#     )
#
#     TestCase.maxDiff = None
#     TestCase().assertDictEqual(test_scan_zip_zip_password_event, scanner.event)
