"""Vulnerabilities view."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient
from harmattan_gui.theme.colors import SEVERITY_COLORS


class VulnerabilitiesView(BaseView):
    TITLE = "Vulnérabilités"
    ICON = "🔓"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        ctrl_row = QHBoxLayout()
        self._scan_btn = QPushButton("🔍  Corrélation CVE")
        self._scan_btn.clicked.connect(self._on_scan)
        ctrl_row.addWidget(self._scan_btn)
        ctrl_row.addStretch()
        self._layout.addLayout(ctrl_row)

        group = QGroupBox("CVE & Findings")
        table_layout = QVBoxLayout()
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(["CVE / Titre", "Hôte", "Score", "Sévérité", "Description"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        table_layout.addWidget(self._table)
        group.setLayout(table_layout)
        self._layout.addWidget(group)

    def _on_scan(self) -> None:
        self._scan_btn.setEnabled(False)
        self._scan_btn.setText("Scan CVE en cours…")
        self._api.post("/api/vuln-scan", callback=self._on_result)

    def _on_result(self, data: dict) -> None:
        self._scan_btn.setEnabled(True)
        self._scan_btn.setText("🔍  Corrélation CVE")
        cves = data.get("cves", data.get("results", []))
        if not cves:
            return
        self._table.setRowCount(len(cves))
        for i, cve in enumerate(cves):
            self._table.setItem(i, 0, QTableWidgetItem(cve.get("id", cve.get("cve_id", ""))))
            self._table.setItem(i, 1, QTableWidgetItem(cve.get("host", "")))
            self._table.setItem(i, 2, QTableWidgetItem(str(cve.get("score", ""))))

            severity = cve.get("severity", "")
            sev_item = QTableWidgetItem(severity)
            color = SEVERITY_COLORS.get(severity.lower(), "#6B7280")
            sev_item.setForeground(QColor(color))
            self._table.setItem(i, 3, sev_item)
            self._table.setItem(i, 4, QTableWidgetItem(cve.get("description", "")[:120]))

    def refresh(self) -> None:
        pass
