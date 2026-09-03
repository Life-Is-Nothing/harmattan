"""Notifications view."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox, QTabWidget,
    QLineEdit, QComboBox, QFormLayout,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient


class NotificationsView(BaseView):
    TITLE = "Notifications"
    ICON = "🔔"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        tabs = QTabWidget()

        # Notification history
        hist_widget = QWidget()
        hist_layout = QVBoxLayout(hist_widget)
        self._refresh_btn = QPushButton("🔄  Rafraîchir")
        self._refresh_btn.clicked.connect(self.refresh)
        hist_layout.addWidget(self._refresh_btn)
        self._notif_table = QTableWidget()
        self._notif_table.setColumnCount(3)
        self._notif_table.setHorizontalHeaderLabels(["Heure", "Type", "Message"])
        self._notif_table.horizontalHeader().setStretchLastSection(True)
        self._notif_table.setAlternatingRowColors(True)
        hist_layout.addWidget(self._notif_table)
        tabs.addTab(hist_widget, "Historique")

        # Alert rules
        rules_widget = QWidget()
        rules_layout = QVBoxLayout(rules_widget)
        self._rules_table = QTableWidget()
        self._rules_table.setColumnCount(3)
        self._rules_table.setHorizontalHeaderLabels(["Nom", "Type événement", "Webhook"])
        self._rules_table.horizontalHeader().setStretchLastSection(True)
        rules_layout.addWidget(self._rules_table)
        tabs.addTab(rules_widget, "Règles d'alerte")

        # Notification channels
        chan_widget = QWidget()
        chan_layout = QVBoxLayout(chan_widget)

        # Add channel form
        form = QFormLayout()
        self._canal_combo = QComboBox()
        self._canal_combo.addItems(["slack", "discord", "email", "syslog"])
        form.addRow("Canal:", self._canal_combo)
        self._label_input = QLineEdit()
        self._label_input.setPlaceholderText("Mon canal Slack")
        form.addRow("Label:", self._label_input)
        self._webhook_input = QLineEdit()
        self._webhook_input.setPlaceholderText("URL du webhook")
        form.addRow("Webhook URL:", self._webhook_input)
        self._events_input = QLineEdit("*")
        form.addRow("Événements:", self._events_input)
        self._add_btn = QPushButton("➕  Ajouter le canal")
        self._add_btn.clicked.connect(self._on_add_channel)
        form.addRow("", self._add_btn)
        chan_layout.addLayout(form)

        # Channels list
        self._channels_table = QTableWidget()
        self._channels_table.setColumnCount(4)
        self._channels_table.setHorizontalHeaderLabels(["Canal", "Label", "Événements", "Statut"])
        self._channels_table.horizontalHeader().setStretchLastSection(True)
        chan_layout.addWidget(self._channels_table)
        tabs.addTab(chan_widget, "Canaux de notification")

        self._layout.addWidget(tabs)

    def _on_add_channel(self) -> None:
        canal = self._canal_combo.currentText()
        label = self._label_input.text().strip() or canal
        webhook = self._webhook_input.text().strip()
        events = self._events_input.text().strip() or "*"

        if not webhook and canal in ("slack", "discord"):
            return

        config = {"webhook_url": webhook} if webhook else {}
        self._api.post("/api/v1/notification-channels", {
            "canal": canal, "label": label,
            "config": config, "events": events,
        }, callback=lambda d: self._load_channels())

    def _load_channels(self) -> None:
        self._api.get("/api/v1/notification-channels", callback=self._on_channels)

    def _on_channels(self, data: list) -> None:
        self._channels_table.setRowCount(len(data))
        for i, ch in enumerate(data):
            self._channels_table.setItem(i, 0, QTableWidgetItem(ch.get("canal", "")))
            self._channels_table.setItem(i, 1, QTableWidgetItem(ch.get("label", "")))
            self._channels_table.setItem(i, 2, QTableWidgetItem(ch.get("events", "*")))
            enabled = ch.get("enabled", 0)
            self._channels_table.setItem(i, 3, QTableWidgetItem("✓ Actif" if enabled else "✗ Désactivé"))

    def refresh(self) -> None:
        self._api.get_notifications(callback=self._on_notifications)
        self._load_channels()

    def _on_notifications(self, data: list) -> None:
        self._notif_table.setRowCount(min(len(data), 200))
        for i, n in enumerate(data[:200]):
            self._notif_table.setItem(i, 0, QTableWidgetItem(str(n.get("time", ""))[-12:]))
            self._notif_table.setItem(i, 1, QTableWidgetItem(n.get("type", "")))
            payload = n.get("payload", {})
            msg = payload.get("title", payload.get("message", ""))
            self._notif_table.setItem(i, 2, QTableWidgetItem(str(msg)[:100]))
