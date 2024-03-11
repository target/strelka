import datetime
import gzip
import io
import os
import tarfile
import typing
from pathlib import Path
from zipfile import ZipFile

import magic
import py7zr
import requests

from strelka.strelka import File


def run_test_scan(
    mocker,
    scan_class,
    fixture_fileobj: typing.IO = None,
    fixture_path: str = None,
    options=None,
    backend_cfg=None,
):
    if options is None:
        options = {}
    if "scanner_timeout" not in options:
        options["scanner_timeout"] = 30
    if backend_cfg is None:
        backend_cfg = {"limits": {"scanner": 30}}

    scanner = scan_class(backend_cfg, "test_coordinate")

    mocker.patch.object(scanner.__class__, "upload_to_coordinator", return_value=None)

    if fixture_path:
        data = Path(fixture_path).read_bytes()
    elif fixture_fileobj:
        data = fixture_fileobj.read()
    else:
        data = None

    scanner.scan_wrapper(
        data=data,
        file=File(name=fixture_path if fixture_path else "test"),
        options=options,
        expire_at=datetime.date.today(),
    )

    # If a scanner outputs IOCs, append them to the event for test coverage
    if scanner.iocs:
        scanner.event.update({"iocs": scanner.iocs})

    return scanner.event


def get_remote_fixture(url: str, session: requests.Session = None) -> io.BytesIO:
    """Download a fixture from a URL"""

    # Get a streamed version of the downloaded file
    if session:
        response = session.get(url, stream=True)
    else:
        response = requests.get(url, stream=True)

    response.raw.decode_content = True

    # Convert the raw file-like object to a real BytesIO object
    bytesfile = io.BytesIO()
    bytesfile.write(response.raw.read())
    bytesfile.seek(0)

    return bytesfile


def get_remote_fixture_archive(
    url: str, session: requests.Session = None, password: str = None
) -> [dict[str, io.BytesIO]]:
    """Decompress zip, 7zip, gzip, tar+gzip remote fixtures with an optional password"""
    bytesfile: io.BytesIO = get_remote_fixture(url, session)

    mime: magic.Magic = magic.Magic(mime=True)
    mime_type: str = mime.from_buffer(bytesfile.read())
    bytesfile.seek(0)

    allfiles: dict[str, typing.IO] = {}

    if mime_type == "application/zip":
        try:
            with ZipFile(bytesfile) as archive:
                for fileentry in archive.filelist:
                    if not fileentry.is_dir():
                        allfiles.update(
                            {
                                fileentry.filename: io.BytesIO(
                                    archive.read(
                                        fileentry.filename,
                                        pwd=(
                                            password.encode("utf-8")
                                            if password
                                            else None
                                        ),
                                    )
                                )
                            }
                        )
        except Exception as e:
            raise e

    elif mime_type == "application/x-7z-compressed":
        try:
            with py7zr.SevenZipFile(bytesfile, password=password) as archive:
                allfiles = archive.readall()
        except Exception as e:
            raise e

    elif mime_type == "application/gzip":
        try:
            with gzip.open(bytesfile) as archive:
                allfiles.update(
                    {os.path.basename(url).rstrip(".gz"): io.BytesIO(archive.read())}
                )

        except Exception as e:
            raise e

    elif mime_type == "application/x-tar":
        try:
            with tarfile.open(fileobj=bytesfile) as archive:
                for member in archive.getmembers():
                    if member.isfile():
                        allfiles.update({member.name: archive.extractfile(member)})

        except Exception as e:
            raise e

    else:
        raise ValueError(f"Archive type {mime_type} not supported")

    return allfiles
