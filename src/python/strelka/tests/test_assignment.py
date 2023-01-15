import redis
import yaml

from pathlib import Path
from unittest import TestCase

from strelka import strelka


def test_assignment():
    """
    Pass: All test fixtures match the given non-wildcard scanner assignments.
    Failure: At least one test fixture does not match the given scanner assignment.
    """

    # Scanners that apply to all files (*) are not included
    test_assignments = {
        "test.7z": ["ScanLibarchive"],
        "test.b64": ["ScanUrl"],
        "test.bat": ["ScanBatch"],
        "test.bz2": ["ScanBzip2"],
        "test.cpio": ["ScanLibarchive"],
        "test.deb": ["ScanLibarchive"],
        "test.der": ["ScanX509"],
        "test.dmg": ["ScanDmg"],
        "test.doc": ["ScanEncryptedZip", "ScanExiftool", "ScanOle", "ScanVba"],
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
        "test.lnk": ["ScanExiftool", "ScanLNK"],
        "test.macho": ["ScanMacho"],
        "test.msi": ["ScanExiftool", "ScanOle", "ScanVba"],  # Needs CDF subtype
        "test.pdf": ["ScanExiftool", "ScanPdf"],
        "test.pem": ["ScanUrl", "ScanX509"],
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
        "test.txt": ["ScanUrl"],
        "test.url": ["ScanUrl"],
        "test.vhd": ["ScanVhd"],
        "test.vhdx": ["ScanVhd"],
        "test.xar": ["ScanLibarchive"],
        "test.xml": ["ScanXml"],
        "test.xz": ["ScanLzma"],
        "test.yara": ["ScanUrl"],
        "test.zip": ["ScanZip"],
        "test_aes256_password.zip": ["ScanEncryptedZip", "ScanZip"],
        "test_broken_iend.png": [
            "ScanExiftool",
            "ScanLsb",
            "ScanNf",
            "ScanOcr",
            "ScanPngEof",
            "ScanQr",
        ],
        "test_lzx.cab": ["ScanLibarchive"],
        "test_manifest.json": ["ScanJson", "ScanManifest"],
        "test_password.doc": ["ScanEncryptedZip", "ScanExiftool", "ScanOle", "ScanVba"],
        "test_password.docx": [
            "ScanEncryptedDoc",
            "ScanExiftool",
            "ScanOle",
            "ScanVba",
        ],
        "test_password_brute.doc": [
            "ScanEncryptedZip",
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
        "test_pe.b64": ["ScanBase64PE", "ScanUrl"],
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
        "test_pii.csv": [],  # ScanCcn not enabled
        "test_qr.png": [
            "ScanExiftool",
            "ScanLsb",
            "ScanNf",
            "ScanOcr",
            "ScanPngEof",
            "ScanQr",
        ],
        "test_readonly.dmg": ["ScanDmg"],
        "test_readwrite.dmg": [],  # No taste
        "test_text.jpg": [
            "ScanExiftool",
            "ScanJpeg",
            "ScanLsb",
            "ScanNf",
            "ScanOcr",
            "ScanQr",
        ],
        "test_upx.exe": ["ScanPe", "ScanUpx"],
        "test_xor.exe": ["ScanPe"],
        "test_zip.cab": ["ScanLibarchive"],
        "test_zip_password.zip": ["ScanEncryptedZip", "ScanZip"],
    }

    test_fixtures = sorted(
        list(Path(Path(__file__).parent / "fixtures/").glob("test*"))
    )

    backend_cfg_path: str = "/etc/strelka/backend.yaml"

    with open(backend_cfg_path, "r") as f:
        backend_cfg = yaml.safe_load(f.read())

        coordinator = redis.StrictRedis(host="127.0.0.1", port=65535, db=0)

        backend = strelka.Backend(backend_cfg, coordinator)

        assignments = {}

        for test_fixture in test_fixtures:
            with open(
                Path(Path(__file__).parent / f"fixtures/{test_fixture.name}"), "rb"
            ) as test_file:
                entries = []
                data = test_file.read()
                file = strelka.File()
                file.add_flavors(backend.match_flavors(data))
                matches = backend.match_scanners(file, ignore_wildcards=True)
                for match in matches:
                    entries.append(match.get("name", "__missing__"))
                assignments[test_fixture.name] = entries

        TestCase.maxDiff = None
        TestCase().assertDictEqual(test_assignments, assignments)
