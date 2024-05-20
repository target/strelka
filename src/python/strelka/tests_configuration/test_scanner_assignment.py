import os
from pathlib import Path
from unittest import TestCase

import pytest
import yaml

from strelka import strelka

# Scanners that apply to all files (*) are not included
test_assignments_expected: dict = {
    "test.7z": ["ScanSevenZip"],
    "test.b64": ["ScanUrl"],
    "test.bat": ["ScanBatch"],
    "test.bz2": ["ScanBzip2"],
    "test.cpio": ["ScanLibarchive"],
    "test.deb": ["ScanLibarchive"],
    "test.der": ["ScanX509"],
    "test.dmg": ["ScanDmg"],
    "test.doc": ["ScanExiftool", "ScanOle", "ScanVba"],
    "test.docx": ["ScanDocx", "ScanZip"],
    "test.elf": [],
    "test.eml": ["ScanEmail"],
    "test.empty": [],
    "test.exe": ["ScanPe"],
    "test.gif": ["ScanExiftool", "ScanGif"],
    "test.gz": ["ScanGzip"],
    "test.html": ["ScanHtml"],
    "test.ini": ["ScanUrl"],
    "test.iso": ["ScanIso"],
    "test.jpg": [
        "ScanExiftool",
        "ScanJpeg",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanQr",
    ],
    "test.js": ["ScanJavascript"],
    "test.json": ["ScanJson"],
    "test.lnk": ["ScanExiftool", "ScanLnk"],
    "test.macho": ["ScanMacho"],
    "test.msi": [
        "ScanExiftool",
        "ScanMsi",
        "ScanOle",
        "ScanVba",
        "ScanSevenZip",
    ],  # TODO: Needs CDF subtype
    "test.one": ["ScanOnenote"],
    "test.onepkg": ["ScanLibarchive"],
    "test.pcap": ["ScanPcap"],
    "test.pcapng": ["ScanPcap"],
    "test.pdf": ["ScanExiftool", "ScanPdf"],
    "test.pem": ["ScanUrl", "ScanX509"],
    "test.plist": ["ScanPlist", "ScanXml"],
    "test.png": [
        "ScanExiftool",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanPngEof",
        "ScanQr",
    ],
    "test.rar": ["ScanRar"],
    "test.tar": ["ScanTar"],
    "test.tlsh": ["ScanMacho"],
    "test.txt": ["ScanUrl"],
    "test.txt.asc": ["ScanPgp"],
    "test.txt.gpg": [],  # FIXME: Need binary PGP yara signature
    "test.url": ["ScanUrl"],
    "test.vhd": ["ScanVhd"],
    "test.vhdx": ["ScanVhd"],
    "test.webp": ["ScanExiftool", "ScanLsb", "ScanNf", "ScanOcr", "ScanQr"],
    "test.xar": ["ScanLibarchive"],
    "test.xls": ["ScanExiftool", "ScanOle", "ScanVba", "ScanXl4ma"],
    "test.xml": ["ScanXml"],
    "test.xz": ["ScanLzma"],
    "test.yara": ["ScanUrl"],
    "test.zip": ["ScanZip"],
    "test_aes256_password.zip": ["ScanEncryptedZip", "ScanZip"],
    "test_broken.heic": ["ScanExiftool", "ScanTranscode"],
    "test_broken_iend.png": [
        "ScanExiftool",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanPngEof",
        "ScanQr",
    ],
    "test_classic.doc": ["ScanExiftool", "ScanOle", "ScanVba"],
    "test_embed_rar.jpg": [
        "ScanExiftool",
        "ScanJpeg",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanQr",
    ],
    "test_embed_rar.png": [
        "ScanExiftool",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanPngEof",
        "ScanQr",
    ],
    "test_hyperlinks.html": ["ScanHtml"],
    "test_lzx.cab": ["ScanLibarchive"],
    "test_manifest.json": ["ScanJson", "ScanManifest"],
    "test_password.7z": ["ScanSevenZip"],
    "test_password.doc": ["ScanExiftool", "ScanOle", "ScanVba"],
    "test_password.docx": [
        "ScanEncryptedDoc",
        "ScanExiftool",
        "ScanOle",
        "ScanVba",
    ],
    "test_password_brute.7z": ["ScanSevenZip"],
    "test_password_brute.doc": [
        "ScanExiftool",
        "ScanOle",
        "ScanVba",
    ],
    "test_password_brute.docx": [
        "ScanEncryptedDoc",
        "ScanExiftool",
        "ScanOle",
        "ScanVba",
    ],
    "test_password_filenames.7z": ["ScanSevenZip"],
    "test_pe.b64": ["ScanBase64PE", "ScanUrl"],
    "test_pe_object.doc": [
        "ScanExiftool",
        "ScanOle",
        "ScanVba",
    ],
    "test_pe_object_classic.doc": [
        "ScanExiftool",
        "ScanOle",
        "ScanVba",
    ],
    "test_pe_overlay.bmp": [
        "ScanBmpEof",
        "ScanExiftool",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanQr",
    ],
    "test_pe_overlay.jpg": [
        "ScanExiftool",
        "ScanJpeg",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanQr",
    ],
    "test_pe_overlay.png": [
        "ScanExiftool",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanPngEof",
        "ScanQr",
    ],
    "test_pii.csv": [],  # NOTE: ScanCcn not enabled
    "test_private.pgp": ["ScanPgp"],
    "test_public.pgp": ["ScanPgp"],
    "test_qr.avif": ["ScanExiftool", "ScanTranscode"],
    "test_qr.heic": ["ScanExiftool", "ScanTranscode"],
    "test_qr.heif": ["ScanExiftool", "ScanTranscode"],
    "test_qr.jpg": [
        "ScanExiftool",
        "ScanJpeg",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanQr",
    ],
    "test_qr.png": [
        "ScanExiftool",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanPngEof",
        "ScanQr",
    ],
    "test_qr.webp": ["ScanExiftool", "ScanLsb", "ScanNf", "ScanOcr", "ScanQr"],
    "test_readonly.dmg": ["ScanDmg"],
    "test_readwrite.dmg": [],  # FIXME: Should be assigned to a scanner
    "test_text.jpg": [
        "ScanExiftool",
        "ScanJpeg",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanQr",
    ],
    "test_text.png": [
        "ScanExiftool",
        "ScanLsb",
        "ScanNf",
        "ScanOcr",
        "ScanPngEof",
        "ScanQr",
    ],
    "test_text.webp": ["ScanExiftool", "ScanLsb", "ScanNf", "ScanOcr", "ScanQr"],
    "test_udf_1.50.img": ["ScanUdf"],
    "test_upx.exe": ["ScanPe", "ScanUpx"],
    "test_xor.exe": ["ScanPe"],
    "test_zip.cab": ["ScanLibarchive"],
    "test_zip_password.zip": ["ScanEncryptedZip", "ScanZip"],
}


@pytest.mark.parametrize(
    "fixture_path,expected", [(k, v) for k, v in test_assignments_expected.items()]
)
def test_fixture_scanner_assignment(fixture_path, expected) -> None:
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

        assignments = []

        with open(
            Path(Path(__file__).parent / f"../tests/fixtures/{fixture_path}"), "rb"
        ) as test_file:
            data = test_file.read()
            file = strelka.File()
            file.add_flavors(backend.match_flavors(data))
            matches = backend.match_scanners(file, ignore_wildcards=True)
            for match in matches:
                assignments.append(match.get("name", "__missing__"))

            TestCase.maxDiff = None
            TestCase().assertListEqual(expected, assignments)
