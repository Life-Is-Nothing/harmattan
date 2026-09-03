"""ARP Scan view."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QGroupBox, QComboBox,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient


class ArpScanView(BaseView):
    TITLE = "Découverte ARP"
    ICON = "📡"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        # Controls
        ctrl_row = QHBoxLayout()
        self._subnet_input = QLineEdit("192.168.1.0/24")
        self._subnet_input.setPlaceholderText("Sous-réseau (CIDR)")
        ctrl_row.addWidget(QLabel("Subnet:"))
        ctrl_row.addWidget(self._subnet_input, 1)

        self._enrich_cb = QCheckBox("Enrichir")
        self._enrich_cb.setChecked(True)
        ctrl_row.addWidget(self._enrich_cb)

        self._scan_btn = QPushButton("🚀  Scan ARP")
        self._scan_btn.clicked.connect(self._on_scan)
        ctrl_row.addWidget(self._scan_btn)
        self._layout.addLayout(ctrl_row)

        # Results table
        table_group = QGroupBox("Résultats")
        table_layout = QVBoxLayout()
        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels(["IP", "MAC", "Vendeur", "Hostname", "Rôle", "Première vue"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        table_layout.addWidget(self._table)
        table_group.setLayout(table_layout)
        self._layout.addWidget(table_group)

    def _on_scan(self) -> None:
        subnet = self._subnet_input.text().strip()
        if not subnet:
            return
        self._scan_btn.setEnabled(False)
        self._scan_btn.setText("Scan en cours…")
        self._api.run_arp_scan(subnet, enrich=self._enrich_cb.isChecked(),
                               callback=self._on_result, errback=lambda e: None)

    def _on_result(self, data: dict) -> None:
        self._scan_btn.setEnabled(True)
        self._scan_btn.setText("🚀  Scan ARP")
        hosts = data.get("hosts", data.get("results", []))
        if not hosts:
            return
        self._table.setRowCount(len(hosts))
        for i, host in enumerate(hosts):
            self._table.setItem(i, 0, QTableWidgetItem(host.get("ip", "")))
            self._table.setItem(i, 1, QTableWidgetItem(host.get("mac", "")))
            self._table.setItem(i, 2, QTableWidgetItem(host.get("vendor", "")[:30]))
            self._table.setItem(i, 3, QTableWidgetItem(host.get("hostname", "")))
            self._table.setItem(i, 4, QTableWidgetItem(host.get("role", "")))
            self._table.setItem(i, 5, QTableWidgetItem(host.get("first_seen", "")))

    def refresh(self) -> None:
        pass
