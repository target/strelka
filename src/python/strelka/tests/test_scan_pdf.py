"""
Tests for ScanPdf scanner, focusing on password-protected PDF handling.

Run with:
    PYTHONPATH=src/python uv run pytest src/python/strelka/tests/test_scan_pdf.py -v
"""
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from strelka.scanners.scan_pdf import ScanPdf
from strelka.strelka import File


FIXTURES = Path(__file__).parent / "fixtures"
BACKEND_CFG = {"limits": {"scanner": 30}}
EXPIRE_AT = int(time.time()) + 300


@pytest.fixture
def scanner():
    coordinator = MagicMock()
    coordinator.pipeline.return_value = MagicMock()
    return ScanPdf(BACKEND_CFG, coordinator)


@pytest.fixture
def normal_pdf():
    with open(FIXTURES / "test.pdf", "rb") as f:
        return f.read()


@pytest.fixture
def encrypted_pdf():
    with open(FIXTURES / "test_encrypted.pdf", "rb") as f:
        return f.read()


class TestScanPdfUnencrypted:
    def test_no_encryption_flags_without_password(self, scanner, normal_pdf):
        """Unencrypted PDF produces no password-related flags."""
        file = File(name="test.pdf")
        _, result = scanner.scan_wrapper(normal_pdf, file, {}, EXPIRE_AT)
        event = result["pdf"]

        assert "decrypted_with_password" not in event["flags"]
        assert "encrypted_pdf_no_password" not in event["flags"]
        assert "password_auth_failed" not in event["flags"]
        assert "pdf_load_error" not in event["flags"]

    def test_no_encryption_flags_with_password(self, scanner, normal_pdf):
        """Unencrypted PDF with an unnecessary password ignores it."""
        file = File(name="test.pdf")
        options = {"metadata": {"password": "unnecessary"}}
        _, result = scanner.scan_wrapper(normal_pdf, file, options, EXPIRE_AT)
        event = result["pdf"]

        assert "decrypted_with_password" not in event["flags"]
        assert "encrypted_pdf_no_password" not in event["flags"]
        assert "password_auth_failed" not in event["flags"]
        assert "pdf_load_error" not in event["flags"]

    def test_produces_totals(self, scanner, normal_pdf):
        """Unencrypted PDF initializes the total counters."""
        file = File(name="test.pdf")
        _, result = scanner.scan_wrapper(normal_pdf, file, {}, EXPIRE_AT)
        event = result["pdf"]

        assert "total" in event
        assert "objects" in event["total"]
        assert "extracted" in event["total"]

    def test_extracts_uris(self, scanner, normal_pdf):
        """Unencrypted PDF extracts annotated URIs."""
        file = File(name="test.pdf")
        _, result = scanner.scan_wrapper(normal_pdf, file, {}, EXPIRE_AT)
        event = result["pdf"]

        assert "https://example.com/test" in event.get("annotated_uris", [])


class TestScanPdfEncrypted:
    def test_correct_password_decrypts(self, scanner, encrypted_pdf):
        """Encrypted PDF with correct password sets decrypted flag."""
        file = File(name="test_encrypted.pdf")
        options = {"metadata": {"password": "test_password"}}
        _, result = scanner.scan_wrapper(encrypted_pdf, file, options, EXPIRE_AT)
        event = result["pdf"]

        assert "decrypted_with_password" in event["flags"]
        assert "password_auth_failed" not in event["flags"]
        assert "encrypted_pdf_no_password" not in event["flags"]
        assert "pdf_load_error" not in event["flags"]

    def test_correct_password_produces_totals(self, scanner, encrypted_pdf):
        """Encrypted PDF decrypted with correct password initializes totals."""
        file = File(name="test_encrypted.pdf")
        options = {"metadata": {"password": "test_password"}}
        _, result = scanner.scan_wrapper(encrypted_pdf, file, options, EXPIRE_AT)
        event = result["pdf"]

        assert "total" in event
        assert event["total"]["extracted"] >= 0

    def test_correct_password_extracts_uris(self, scanner, encrypted_pdf):
        """Encrypted PDF with correct password extracts URIs."""
        file = File(name="test_encrypted.pdf")
        options = {"metadata": {"password": "test_password"}}
        _, result = scanner.scan_wrapper(encrypted_pdf, file, options, EXPIRE_AT)
        event = result["pdf"]

        assert "https://example.com/encrypted" in event.get("annotated_uris", [])

    def test_wrong_password_flags_failure(self, scanner, encrypted_pdf):
        """Encrypted PDF with wrong password flags auth failure."""
        file = File(name="test_encrypted.pdf")
        options = {"metadata": {"password": "wrong_password"}}
        _, result = scanner.scan_wrapper(encrypted_pdf, file, options, EXPIRE_AT)
        event = result["pdf"]

        assert "password_auth_failed" in event["flags"]
        assert "decrypted_with_password" not in event["flags"]

    def test_wrong_password_no_extraction(self, scanner, encrypted_pdf):
        """Encrypted PDF with wrong password does not extract objects."""
        file = File(name="test_encrypted.pdf")
        options = {"metadata": {"password": "wrong_password"}}
        files, result = scanner.scan_wrapper(encrypted_pdf, file, options, EXPIRE_AT)

        assert len(files) == 0

    def test_no_password_flags_missing(self, scanner, encrypted_pdf):
        """Encrypted PDF with no password flags appropriately."""
        file = File(name="test_encrypted.pdf")
        _, result = scanner.scan_wrapper(encrypted_pdf, file, {}, EXPIRE_AT)
        event = result["pdf"]

        assert "encrypted_pdf_no_password" in event["flags"]
        assert "decrypted_with_password" not in event["flags"]

    def test_no_password_no_extraction(self, scanner, encrypted_pdf):
        """Encrypted PDF with no password does not extract objects."""
        file = File(name="test_encrypted.pdf")
        files, result = scanner.scan_wrapper(encrypted_pdf, file, {}, EXPIRE_AT)

        assert len(files) == 0

    def test_metadata_without_password_key(self, scanner, encrypted_pdf):
        """Encrypted PDF with metadata but no password key flags missing."""
        file = File(name="test_encrypted.pdf")
        options = {"metadata": {"other_key": "value"}}
        _, result = scanner.scan_wrapper(encrypted_pdf, file, options, EXPIRE_AT)
        event = result["pdf"]

        assert "encrypted_pdf_no_password" in event["flags"]
