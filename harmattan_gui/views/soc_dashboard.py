"""SOC Dashboard view — real-time network monitoring."""
from __future__ import annotations

from typing import Any

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGridLayout, QGroupBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton, QFrame,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient
from harmattan_gui.api import endpoints as E


class StatusPill(QFrame):
    """Colored status indicator pill."""

    def __init__(self, label: str, ok: bool = False, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        color = "#22C55E" if ok else "#6B7280"
        self.setStyleSheet(f"""
            QFrame {{
                background: #1E293B;
                border: 1px solid {color};
                border-radius: 16px;
                padding: 6px 14px;
                font-size: 12px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 4, 12, 4)
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {color}; font-size: 14px;")
        layout.addWidget(dot)
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #F1F5F9;")
        layout.addWidget(lbl)


class StatCard(QFrame):
    """Dashboard stat card."""

    def __init__(self, title: str, value: str, color: str = "#0D9488", parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background: #1E293B;
                border: 1px solid #334155;
                border-top: 3px solid {color};
                border-radius: 8px;
                padding: 16px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: bold;")
        layout.addWidget(lbl_title)
        lbl_val = QLabel(value)
        lbl_val.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")
        lbl_val.setFont(QFont("monospace", 28, QFont.Weight.Bold))
        layout.addWidget(lbl_val)


class SocDashboardView(BaseView):
    TITLE = "SOC Dashboard"
    ICON = "📊"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(5000)
        self._refresh_timer.timeout.connect(self._refresh_data)
        self._build_ui()

    def _build_ui(self) -> None:
        # Status pills row
        pill_row = QHBoxLayout()
        self._pill_scapy = StatusPill("Scapy")
        self._pill_nmap = StatusPill("Nmap")
        self._pill_root = StatusPill("Root")
        pill_row.addWidget(self._pill_scapy)
        pill_row.addWidget(self._pill_nmap)
        pill_row.addWidget(self._pill_root)
        pill_row.addStretch()
        self._layout.addLayout(pill_row)

        # Stat cards grid
        grid = QGridLayout()
        grid.setSpacing(12)
        self._card_devices = StatCard("Appareils", "—")
        self._card_exposures = StatCard("Expositions", "—", "#EA580C")
        self._card_critical = StatCard("Risques Critiques", "—", "#DC2626")
        self._card_grade = StatCard("Grade Sécurité", "—", "#3B82F6")
        grid.addWidget(self._card_devices, 0, 0)
        grid.addWidget(self._card_exposures, 0, 1)
        grid.addWidget(self._card_critical, 0, 2)
        grid.addWidget(self._card_grade, 0, 3)
        self._layout.addLayout(grid)

        # Notifications table
        notif_group = QGroupBox("Notifications en direct")
        notif_layout = QVBoxLayout()
        self._notif_table = QTableWidget()
        self._notif_table.setColumnCount(3)
        self._notif_table.setHorizontalHeaderLabels(["Heure", "Type", "Message"])
        self._notif_table.horizontalHeader().setStretchLastSection(True)
        self._notif_table.setAlternatingRowColors(True)
        notif_layout.addWidget(self._notif_table)
        notif_group.setLayout(notif_layout)
        self._layout.addWidget(notif_group)

        # Network info
        self._net_label = QLabel("Réseau: —")
        self._net_label.setStyleSheet("color: #64748B; font-size: 12px;")
        self._layout.addWidget(self._net_label)

    def on_activate(self) -> None:
        self._refresh_timer.start()

    def refresh(self) -> None:
        self._refresh_data()

    def _refresh_data(self) -> None:
        self._api.check_health(callback=self._on_health)
        self._api.get_network_info(callback=self._on_network_info)
        self._api.get_notifications(callback=self._on_notifications)

    def _on_health(self, data: dict) -> None:
        self._pill_scapy.setStyleSheet(self._pill_style(data.get("scapy", False)))
        self._pill_nmap.setStyleSheet(self._pill_style(data.get("nmap", False)))
        root_ok = (data.get("preflight") or {}).get("running_as_root", False)
        self._pill_root.setStyleSheet(self._pill_style(root_ok))
        hosts = data.get("known_hosts", 0)
        self._card_devices.findChildren(QLabel)[1].setText(str(hosts))

    def _pill_style(self, ok: bool) -> str:
        color = "#22C55E" if ok else "#6B7280"
        return f"""
            QFrame {{
                background: #1E293B;
                border: 1px solid {color};
                border-radius: 16px;
                padding: 6px 14px;
                font-size: 12px;
            }}
        """

    def _on_network_info(self, data: dict) -> None:
        subnet = data.get("subnet", "—")
        ssid = data.get("ssid", "—")
        gw = data.get("gateway", "—")
        self._net_label.setText(f"Réseau: {subnet} | SSID: {ssid} | Passerelle: {gw}")

    def _on_notifications(self, data: list) -> None:
        if not data:
            return
        self._notif_table.setRowCount(min(len(data), 100))
        for i, notif in enumerate(data[:100]):
            self._notif_table.setItem(i, 0, QTableWidgetItem(notif.get("time", "")[-8:]))
            ev_type = notif.get("type", "message")
            self._notif_table.setItem(i, 1, QTableWidgetItem(ev_type))
            payload = notif.get("payload", {})
            msg = payload.get("title", payload.get("message", ""))
            self._notif_table.setItem(i, 2, QTableWidgetItem(str(msg)[:80]))
