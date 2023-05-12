import os
from pathlib import Path
from unittest import TestCase

import pytest
import yaml
from pytest_unordered import unordered

from strelka import strelka

taste_expectations: dict = {
    "test.7z": {"mime": ["application/x-7z-compressed"], "yara": ["_7zip_file"]},
    "test_qr.avif": {"mime": ["image/avif"], "yara": []},
    "test.b64": {"mime": ["text/plain"], "yara": []},  # FIXME: No file-specific match
    "test.bat": {
        "mime": ["text/x-msdos-batch"],
        "yara": [],
    },  # FIXME: Not in backend.cfg
    "test.bz2": {"mime": ["application/x-bzip2"], "yara": ["bzip2_file"]},
    "test.cpio": {"mime": ["application/x-cpio"], "yara": []},
    "test.deb": {
        "mime": ["application/vnd.debian.binary-package"],
        "yara": ["debian_package_file"],
    },
    "test.der": {"mime": ["application/octet-stream"], "yara": ["x509_der_file"]},
    "test.dmg": {"mime": ["application/octet-stream"], "yara": ["hfsplus_disk_image"]},
    "test.doc": {"mime": ["application/msword"], "yara": ["olecf_file"]},
    "test.docx": {
        "mime": [
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ],
        "yara": ["ooxml_file"],
    },
    "test.elf": {"mime": ["application/x-sharedlib"], "yara": ["elf_file"]},
    "test.eml": {"mime": ["message/rfc822"], "yara": ["email_file"]},
    "test.empty": {"mime": ["application/x-empty"], "yara": []},
    "test.exe": {"mime": ["application/x-dosexec"], "yara": ["mz_file"]},
    "test.gif": {"mime": ["image/gif"], "yara": ["gif_file"]},
    "test.gz": {"mime": ["application/gzip"], "yara": ["gzip_file"]},
    "test_qr.heic": {"mime": ["image/heic"], "yara": []},
    "test_qr.heif": {"mime": ["image/heif"], "yara": []},
    "test.html": {"mime": ["text/html"], "yara": ["html_file"]},
    "test.ini": {"mime": ["text/plain"], "yara": ["ini_file"]},
    "test.iso": {"mime": ["application/x-iso9660-image"], "yara": ["iso_file"]},
    "test.jpg": {"mime": ["image/jpeg"], "yara": ["jpeg_file"]},
    "test.js": {"mime": ["text/plain"], "yara": ["javascript_file"]},
    "test.json": {"mime": ["application/json"], "yara": ["json_file"]},
    "test.lnk": {"mime": ["application/octet-stream"], "yara": ["lnk_file"]},
    "test.macho": {"mime": ["application/x-mach-binary"], "yara": ["macho_file"]},
    "test.msi": {
        "mime": ["application/vnd.ms-msi"],
        "yara": ["olecf_file"],
    },  # TODO: CDF format needs subtypes
    "test.one": {"mime": ["application/octet-stream"], "yara": ["onenote_file"]},
    "test.onepkg": {
        "mime": ["application/vnd.ms-cab-compressed"],
        "yara": ["cab_file"],
    },
    "test.pcap": {"mime": ["application/vnd.tcpdump.pcap"], "yara": ["pcap_file"]},
    "test.pcapng": {
        "mime": ["application/octet-stream"],
        "yara": ["pcapng_file"],
    },
    "test.pdf": {"mime": ["application/pdf"], "yara": ["pdf_file"]},
    "test.pem": {"mime": ["text/plain"], "yara": ["x509_pem_file"]},
    "test.plist": {"mime": ["text/xml"], "yara": unordered(["plist_file", "xml_file"])},
    "test.png": {"mime": ["image/png"], "yara": ["png_file"]},
    "test.rar": {"mime": ["application/x-rar"], "yara": ["rar_file"]},
    "test.tar": {"mime": ["application/x-tar"], "yara": ["tar_file"]},
    "test.tlsh": {
        "mime": ["application/x-mach-binary"],
        "yara": unordered(["macho_file", "credit_cards"]),
    },
    "test.txt": {"mime": ["text/plain"], "yara": []},
    "test.txt.asc": {"mime": ["text/PGP"], "yara": ["pgp_file"]},
    "test.txt.gpg": {
        "mime": ["application/octet-stream"],
        "yara": [],
    },  # FIXME: Need binary PGP yara signature
    "test.url": {"mime": ["text/plain"], "yara": []},
    "test.vhd": {"mime": ["application/octet-stream"], "yara": ["vhd_file"]},
    "test.vhdx": {"mime": ["application/octet-stream"], "yara": ["vhdx_file"]},
    "test.webp": {"mime": ["image/webp"], "yara": []},
    "test.xar": {"mime": ["application/x-xar"], "yara": ["xar_file"]},
    "test.xls": {
        "mime": ["application/vnd.ms-excel"],
        "yara": unordered(["excel4_file", "olecf_file"]),
    },
    "test.xml": {"mime": ["text/xml"], "yara": ["xml_file"]},
    "test.xz": {"mime": ["application/x-xz"], "yara": ["xz_file"]},
    "test.yara": {"mime": ["text/plain"], "yara": []},
    "test.yaml": {"mime": ["text/plain"], "yara": []},
    "test.zip": {"mime": ["application/zip"], "yara": ["zip_file"]},
    "test_aes256_password.zip": {
        "mime": ["application/zip"],
        "yara": unordered(["encrypted_zip", "zip_file"]),
    },
    "test_broken_iend.png": {"mime": ["image/png"], "yara": ["png_file"]},
    "test_classic.doc": {"mime": ["application/msword"], "yara": ["olecf_file"]},
    "test_embed_rar.jpg": {"mime": ["image/jpeg"], "yara": ["jpeg_file"]},
    "test_embed_rar.png": {"mime": ["image/png"], "yara": ["png_file"]},
    "test_broken.heic": {"mime": ["image/heic"], "yara": []},
    "test_hyperlinks.html": {"mime": ["text/html"], "yara": ["html_file"]},
    "test_lzx.cab": {
        "mime": ["application/vnd.ms-cab-compressed"],
        "yara": ["cab_file"],
    },
    "test_manifest.json": {
        "mime": ["application/json"],
        "yara": unordered(["browser_manifest", "json_file"]),
    },
    "test_password.7z": {
        "mime": ["application/x-7z-compressed"],
        "yara": ["_7zip_file"],
    },
    "test_password.doc": {"mime": ["application/msword"], "yara": ["olecf_file"]},
    "test_password.docx": {
        "mime": ["application/encrypted"],
        "yara": unordered(["encrypted_word_document", "olecf_file"]),
    },
    "test_password_brute.7z": {
        "mime": ["application/x-7z-compressed"],
        "yara": ["_7zip_file"],
    },
    "test_password_brute.doc": {"mime": ["application/msword"], "yara": ["olecf_file"]},
    "test_password_brute.docx": {
        "mime": ["application/encrypted"],
        "yara": unordered(["encrypted_word_document", "olecf_file"]),
    },
    "test_password_filenames.7z": {
        "mime": ["application/x-7z-compressed"],
        "yara": ["_7zip_file"],
    },
    "test_pe.b64": {"mime": ["text/plain"], "yara": ["base64_pe"]},
    "test_pe_object.doc": {"mime": ["application/msword"], "yara": ["olecf_file"]},
    "test_pe_object_classic.doc": {
        "mime": ["application/msword"],
        "yara": ["olecf_file"],
    },
    "test_pe_overlay.bmp": {"mime": ["image/bmp"], "yara": ["bmp_file"]},
    "test_pe_overlay.jpg": {"mime": ["image/jpeg"], "yara": ["jpeg_file"]},
    "test_pe_overlay.png": {"mime": ["image/png"], "yara": ["png_file"]},
    "test_pii.csv": {"mime": ["text/csv"], "yara": ["credit_cards"]},
    "test_private.pgp": {"mime": ["application/pgp-keys"], "yara": []},
    "test_public.pgp": {"mime": ["application/pgp-keys"], "yara": ["pgp_file"]},
    "test_qr.jpg": {"mime": ["image/jpeg"], "yara": ["jpeg_file"]},
    "test_qr.png": {"mime": ["image/png"], "yara": ["png_file"]},
    "test_qr.webp": {"mime": ["image/webp"], "yara": []},
    "test_readonly.dmg": {
        "mime": ["application/octet-stream"],
        "yara": ["dmg_disk_image"],
    },
    "test_readwrite.dmg": {"mime": ["application/octet-stream"], "yara": []},
    "test_text.jpg": {"mime": ["image/jpeg"], "yara": ["jpeg_file"]},
    "test_text.png": {"mime": ["image/png"], "yara": ["png_file"]},
    "test_text.webp": {"mime": ["image/webp"], "yara": []},
    "test_udf_1.50.img": {"mime": ["application/octet-stream"], "yara": ["udf_file"]},
    "test_upx.exe": {
        "mime": ["application/x-dosexec"],
        "yara": unordered(["mz_file", "upx_file"]),
    },
    "test_whitespace.html": {"mime": ["text/html"], "yara": ["html_file"]},
    "test.vsto": {"mime": ["text/xml"], "yara": unordered(["vsto_file", "xml_file"])},
    "test_xor.exe": {"mime": ["application/x-dosexec"], "yara": ["mz_file"]},
    "test_zip.cab": {
        "mime": ["application/vnd.ms-cab-compressed"],
        "yara": ["cab_file"],
    },
    "test_zip_password.zip": {
        "mime": ["application/zip"],
        "yara": unordered(["encrypted_zip", "zip_file"]),
    },
}


@pytest.mark.parametrize(
    "fixture_path,expected", [(k, v) for k, v in taste_expectations.items()]
)
def test_fixture_taste_output(fixture_path, expected) -> None:
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

        with open(
            Path(Path(__file__).parent / f"../tests/fixtures/{fixture_path}"), "rb"
        ) as test_file:
            data = test_file.read()
            taste = backend.match_flavors(data)

            TestCase.maxDiff = None
            TestCase().assertDictEqual(expected, taste, msg=fixture_path)


def test_taste_required() -> None:
    """
    Pass: All test fixtures in the given directory have assigned test_taste data.
    Failure: A test fixture file exists that doesn't have a corresponding test_taste entry.
    """

    test_fixtures = sorted(
        list(Path(Path(__file__).parent / "../tests/fixtures/").glob("test*"))
    )

    for test_fixture in test_fixtures:
        TestCase().assertIn(
            os.path.basename(test_fixture),
            taste_expectations.keys(),
            msg="Fixture does not have a taste expectation",
        )
