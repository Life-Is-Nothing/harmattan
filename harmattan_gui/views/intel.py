"""Intel view."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox, QTabWidget,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient
from harmattan_gui.theme.colors import SEVERITY_COLORS


class IntelView(BaseView):
    TITLE = "Intel"
    ICON = "🧠"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        ctrl_row = QHBoxLayout()
        self._refresh_btn = QPushButton("🔄  Rafraîchir Intel")
        self._refresh_btn.clicked.connect(self.refresh)
        ctrl_row.addWidget(self._refresh_btn)
        ctrl_row.addStretch()
        self._layout.addLayout(ctrl_row)

        tabs = QTabWidget()

        # MITRE tab
        mitre_widget = QWidget()
        mitre_layout = QVBoxLayout(mitre_widget)
        self._mitre_table = QTableWidget()
        self._mitre_table.setColumnCount(4)
        self._mitre_table.setHorizontalHeaderLabels(["Technique", "Tactic", "Hôte", "Service"])
        self._mitre_table.horizontalHeader().setStretchLastSection(True)
        mitre_layout.addWidget(self._mitre_table)
        tabs.addTab(mitre_widget, "MITRE ATT&CK")

        # SNMP tab
        snmp_widget = QWidget()
        snmp_layout = QVBoxLayout(snmp_widget)
        self._snmp_btn = QPushButton("📡  Scan SNMP")
        self._snmp_btn.clicked.connect(self._on_snmp)
        snmp_layout.addWidget(self._snmp_btn)
        self._snmp_table = QTableWidget()
        self._snmp_table.setColumnCount(3)
        self._snmp_table.setHorizontalHeaderLabels(["Hôte", "Communauté", "Info"])
        self._snmp_table.horizontalHeader().setStretchLastSection(True)
        snmp_layout.addWidget(self._snmp_table)
        tabs.addTab(snmp_widget, "SNMP")

        # WiFi tab
        wifi_widget = QWidget()
        wifi_layout = QVBoxLayout(wifi_widget)
        self._wifi_btn = QPushButton("📶  Scan WiFi")
        self._wifi_btn.clicked.connect(self._on_wifi)
        wifi_layout.addWidget(self._wifi_btn)
        self._wifi_table = QTableWidget()
        self._wifi_table.setColumnCount(4)
        self._wifi_table.setHorizontalHeaderLabels(["SSID", "BSSID", "Channel", "Security"])
        self._wifi_table.horizontalHeader().setStretchLastSection(True)
        wifi_layout.addWidget(self._wifi_table)
        tabs.addTab(wifi_widget, "WiFi")

        # Anomalies tab
        anom_widget = QWidget()
        anom_layout = QVBoxLayout(anom_widget)
        self._anom_table = QTableWidget()
        self._anom_table.setColumnCount(4)
        self._anom_table.setHorizontalHeaderLabels(["Hôte", "Score", "Type", "Description"])
        self._anom_table.horizontalHeader().setStretchLastSection(True)
        anom_layout.addWidget(self._anom_table)
        tabs.addTab(anom_widget, "Anomalies")

        self._layout.addWidget(tabs)

    def refresh(self) -> None:
        self._api.get("/api/intel/summary", callback=self._on_intel)
        self._api.get_mitre(callback=self._on_mitre)

    def _on_intel(self, data: dict) -> None:
        # Anomalies
        anomalies = data.get("anomalies", [])
        self._anom_table.setRowCount(len(anomalies))
        for i, a in enumerate(anomalies):
            self._anom_table.setItem(i, 0, QTableWidgetItem(a.get("host", "")))
            self._anom_table.setItem(i, 1, QTableWidgetItem(str(a.get("score", ""))))
            self._anom_table.setItem(i, 2, QTableWidgetItem(a.get("type", "")))
            self._anom_table.setItem(i, 3, QTableWidgetItem(a.get("description", "")[:80]))

    def _on_mitre(self, data: dict) -> None:
        techniques = data.get("techniques", data.get("results", []))
        self._mitre_table.setRowCount(len(techniques))
        for i, t in enumerate(techniques):
            self._mitre_table.setItem(i, 0, QTableWidgetItem(t.get("technique", t.get("id", ""))))
            self._mitre_table.setItem(i, 1, QTableWidgetItem(t.get("tactic", "")))
            self._mitre_table.setItem(i, 2, QTableWidgetItem(t.get("host", "")))
            self._mitre_table.setItem(i, 3, QTableWidgetItem(t.get("service", "")))

    def _on_snmp(self) -> None:
        self._api.post("/api/snmp/probe", {}, callback=self._on_snmp_result)

    def _on_snmp_result(self, data: dict) -> None:
        results = data.get("results", data.get("hosts", []))
        self._snmp_table.setRowCount(len(results))
        for i, r in enumerate(results):
            self._snmp_table.setItem(i, 0, QTableWidgetItem(r.get("host", r.get("ip", ""))))
            self._snmp_table.setItem(i, 1, QTableWidgetItem(r.get("community", "")))
            self._snmp_table.setItem(i, 2, QTableWidgetItem(r.get("info", "")[:60]))

    def _on_wifi(self) -> None:
        self._api.get("/api/wifi/scan", callback=self._on_wifi_result)

    def _on_wifi_result(self, data: dict) -> None:
        networks = data.get("networks", data.get("results", []))
        self._wifi_table.setRowCount(len(networks))
        for i, n in enumerate(networks):
            self._wifi_table.setItem(i, 0, QTableWidgetItem(n.get("ssid", "")))
            self._wifi_table.setItem(i, 1, QTableWidgetItem(n.get("bssid", "")))
            self._wifi_table.setItem(i, 2, QTableWidgetItem(str(n.get("channel", ""))))
            self._wifi_table.setItem(i, 3, QTableWidgetItem(n.get("security", "")))
