"""Tests for HTTPS certificate generation."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


class TestHttpsCert:
    def test_cert_generation(self):
        try:
            from core.https_cert import ensure_self_signed_cert
        except ImportError:
            pytest.skip("cryptography not available")
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_dir = Path(tmpdir) / "ssl"
            cert_path, key_path = ensure_self_signed_cert(cert_dir)
            assert cert_path.is_file()
            assert key_path.is_file()
            assert cert_path.stat().st_size > 0
            assert key_path.stat().st_size > 0

    def test_cert_contains_correct_content(self):
        try:
            from core.https_cert import ensure_self_signed_cert
        except ImportError:
            pytest.skip("cryptography not available")
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path, key_path = ensure_self_signed_cert(Path(tmpdir))
            cert_text = cert_path.read_text()
            assert "BEGIN CERTIFICATE" in cert_text
            key_text = key_path.read_text()
            assert "BEGIN PRIVATE KEY" in key_text

    def test_cert_reuses_existing(self):
        try:
            from core.https_cert import ensure_self_signed_cert
        except ImportError:
            pytest.skip("cryptography not available")
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_dir = Path(tmpdir)
            cert1, key1 = ensure_self_signed_cert(cert_dir)
            mtime1 = cert1.stat().st_mtime
            cert2, key2 = ensure_self_signed_cert(cert_dir)
            assert cert1 == cert2
            assert cert2.stat().st_mtime == mtime1
