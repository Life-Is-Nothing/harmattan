"""Nmap Scan view."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox, QComboBox,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient


NMAP_PROFILES = [
    ("quick", "-T4 -F"), ("version", "-T4 -sV"), ("full", "-T4 -p- -sV"),
    ("udp", "-T4 -sU --top-ports 100"), ("vuln", "-T4 -sV --script vuln"),
    ("os", "-T4 -O --osscan-guess"), ("safe", "-T4 -sV --script safe"),
    ("all", "-T4 -A -p-"), ("discovery", "-T4 -sn"), ("slow", "-T2 -sV -p-"),
]


class NmapScanView(BaseView):
    TITLE = "Scan Nmap"
    ICON = "🔍"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        ctrl_row = QHBoxLayout()
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("Cible (IP ou CIDR)")
        ctrl_row.addWidget(QLabel("Cible:"))
        ctrl_row.addWidget(self._target_input, 1)

        self._profile_combo = QComboBox()
        for name, _ in NMAP_PROFILES:
            self._profile_combo.addItem(name)
        ctrl_row.addWidget(QLabel("Profil:"))
        ctrl_row.addWidget(self._profile_combo)

        self._scan_btn = QPushButton("🚀  Lancer Nmap")
        self._scan_btn.clicked.connect(self._on_scan)
        ctrl_row.addWidget(self._scan_btn)
        self._layout.addLayout(ctrl_row)

        # Results
        group = QGroupBox("Résultats Nmap")
        layout = QVBoxLayout()
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(["Hôte", "Port", "État", "Service", "Version"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        layout.addWidget(self._table)
        group.setLayout(layout)
        self._layout.addWidget(group)

    def _on_scan(self) -> None:
        target = self._target_input.text().strip()
        if not target:
            return
        self._scan_btn.setEnabled(False)
        self._scan_btn.setText("Scan en cours…")
        self._api.run_nmap_scan(target, profile=self._profile_combo.currentText(),
                                callback=self._on_result)

    def _on_result(self, data: dict) -> None:
        self._scan_btn.setEnabled(True)
        self._scan_btn.setText("🚀  Lancer Nmap")
        hosts = data.get("hosts", data.get("results", []))
        if not hosts:
            return
        rows = []
        for host in hosts:
            ports = host.get("ports", [])
            if not ports:
                rows.append((host.get("ip", ""), "", "", "", ""))
            for port in ports:
                rows.append((
                    host.get("ip", ""),
                    str(port.get("port", "")),
                    port.get("state", ""),
                    port.get("service", ""),
                    port.get("version", "")[:40],
                ))
        self._table.setRowCount(len(rows))
        for i, (ip, port, state, service, ver) in enumerate(rows):
            self._table.setItem(i, 0, QTableWidgetItem(ip))
            self._table.setItem(i, 1, QTableWidgetItem(port))
            self._table.setItem(i, 2, QTableWidgetItem(state))
            self._table.setItem(i, 3, QTableWidgetItem(service))
            self._table.setItem(i, 4, QTableWidgetItem(ver))

    def refresh(self) -> None:
        pass
