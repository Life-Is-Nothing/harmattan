"""Tests for CSV, XLSX, and Markdown export formats."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from core.export_csv import build_csv_report, build_markdown_report

SAMPLE_DATA = {
    "arp": {"hosts": [
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01", "vendor": "Cisco",
         "hostname": "router", "role": "router", "first_seen": "2026-01-01", "last_seen": "2026-07-01"},
        {"ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:02", "vendor": "Dell",
         "hostname": "server", "role": "server", "first_seen": "2026-01-01", "last_seen": "2026-07-01"},
    ]},
    "attack_surface": {
        "exposures": [
            {"host": "192.168.1.1", "port": "22", "service": "SSH",
             "risk": "haute", "detail": "SSH exposé"},
            {"host": "192.168.1.2", "port": "80", "service": "HTTP",
             "risk": "moyenne", "detail": "HTTP sans TLS"},
        ]
    },
    "vuln": {
        "cves": [
            {"id": "CVE-2024-1234", "score": "7.5", "severity": "haute",
             "description": "Test vulnerability"},
        ]
    },
}


class TestCsvExport:
    def test_build_csv_report_contains_headers(self):
        result = build_csv_report(SAMPLE_DATA)
        assert "HARMATTAN Export" in result
        assert "IP" in result
        assert "MAC" in result

    def test_build_csv_report_contains_hosts(self):
        result = build_csv_report(SAMPLE_DATA)
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        assert "Cisco" in result
        assert "Dell" in result

    def test_build_csv_report_contains_exposures(self):
        result = build_csv_report(SAMPLE_DATA)
        assert "SSH" in result
        assert "HTTP" in result
        assert "CVE-2024-1234" in result

    def test_build_csv_report_empty_data(self):
        result = build_csv_report({})
        assert "HARMATTAN Export" in result

    def test_build_csv_report_handles_missing_keys(self):
        result = build_csv_report({"hosts": [{"ip": "1.2.3.4"}]})
        assert "1.2.3.4" in result


class TestMarkdownExport:
    def test_build_markdown_contains_title(self):
        result = build_markdown_report(SAMPLE_DATA)
        assert "# HARMATTAN Audit Report" in result

    def test_build_markdown_contains_hosts(self):
        result = build_markdown_report(SAMPLE_DATA)
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result


class TestXlsxExport:
    def test_build_xlsx_report_creates_file(self):
        try:
            from core.export_csv import build_xlsx_report
        except ImportError:
            pytest.skip("openpyxl not installed")
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
            try:
                build_xlsx_report(SAMPLE_DATA, tmp.name)
                assert Path(tmp.name).stat().st_size > 0
            finally:
                os.unlink(tmp.name)

    def test_build_xlsx_report_empty_data(self):
        try:
            from core.export_csv import build_xlsx_report
        except ImportError:
            pytest.skip("openpyxl not installed")
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
            try:
                build_xlsx_report({}, tmp.name)
                assert Path(tmp.name).stat().st_size > 0
            finally:
                os.unlink(tmp.name)
