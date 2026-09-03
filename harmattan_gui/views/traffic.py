"""Traffic capture view — Wireshark-style 3-pane layout."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QSplitter, QPlainTextEdit, QComboBox, QLineEdit, QFrame,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient


PROTOCOL_COLORS = {
    "TCP": "#3B82F6", "UDP": "#8B5CF6", "ARP": "#EC4899",
    "ICMP": "#22C55E", "DNS": "#F59E0B", "HTTP": "#0D9488",
    "DHCP": "#6366F1", "TLS": "#3B82F6", "MDNS": "#F97316",
}


class TrafficView(BaseView):
    TITLE = "Trafic Réseau"
    ICON = "📦"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        # Capture controls
        ctrl_row = QHBoxLayout()
        self._oneshot_btn = QPushButton("📥  Capture 10s")
        self._oneshot_btn.clicked.connect(self._on_oneshot)
        ctrl_row.addWidget(self._oneshot_btn)
        self._live_btn = QPushButton("▶  Live")
        self._live_btn.clicked.connect(self._on_live)
        ctrl_row.addWidget(self._live_btn)
        self._stop_btn = QPushButton("⏹  Stop")
        self._stop_btn.clicked.connect(self._on_stop)
        self._stop_btn.setEnabled(False)
        ctrl_row.addWidget(self._stop_btn)
        self._clear_btn = QPushButton("🗑  Vider")
        self._clear_btn.clicked.connect(self._on_clear)
        ctrl_row.addWidget(self._clear_btn)
        self._iface_combo = QComboBox()
        self._iface_combo.addItems(["eth0", "wlan0", "any"])
        ctrl_row.addWidget(QLabel("Interface:"))
        ctrl_row.addWidget(self._iface_combo)
        ctrl_row.addStretch()
        self._layout.addLayout(ctrl_row)

        # 3-pane layout (Wireshark-style)
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Top: Packet list
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)

        filter_row = QHBoxLayout()
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("Filtre d'affichage (ip.addr==192.168.1.1)")
        filter_row.addWidget(self._filter_input)
        self._filter_btn = QPushButton("Appliquer")
        filter_row.addWidget(self._filter_btn)
        top_layout.addLayout(filter_row)

        self._packet_table = QTableWidget()
        self._packet_table.setColumnCount(7)
        self._packet_table.setHorizontalHeaderLabels(["#", "Temps", "Source", "Destination", "Protocole", "Long.", "Info"])
        self._packet_table.horizontalHeader().setStretchLastSection(True)
        self._packet_table.setAlternatingRowColors(True)
        self._packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._packet_table.itemSelectionChanged.connect(self._on_packet_selected)
        top_layout.addWidget(self._packet_table)
        splitter.addWidget(top_widget)

        # Middle: Packet detail
        mid_widget = QWidget()
        mid_layout = QVBoxLayout(mid_widget)
        mid_layout.setContentsMargins(0, 0, 0, 0)
        mid_layout.addWidget(QLabel("Détails du paquet"))
        self._detail_panel = QPlainTextEdit()
        self._detail_panel.setReadOnly(True)
        self._detail_panel.setMaximumBlockCount(200)
        mid_layout.addWidget(self._detail_panel)
        splitter.addWidget(mid_widget)

        # Bottom: Hex dump
        bot_widget = QWidget()
        bot_layout = QVBoxLayout(bot_widget)
        bot_layout.setContentsMargins(0, 0, 0, 0)
        bot_layout.addWidget(QLabel("Hex Dump"))
        self._hex_panel = QPlainTextEdit()
        self._hex_panel.setReadOnly(True)
        self._hex_panel.setMaximumBlockCount(100)
        font = QFont("Cascadia Code", 10)
        self._hex_panel.setFont(font)
        bot_layout.addWidget(self._hex_panel)
        splitter.addWidget(bot_widget)

        splitter.setSizes([400, 200, 200])
        self._layout.addWidget(splitter)

    def _on_oneshot(self) -> None:
        self._oneshot_btn.setEnabled(False)
        self._oneshot_btn.setText("Capture en cours…")
        iface = self._iface_combo.currentText()
        self._api.post("/api/traffic/oneshot", {"iface": iface, "count": 100},
                       callback=self._on_capture_result)

    def _on_live(self) -> None:
        iface = self._iface_combo.currentText()
        self._api.post("/api/traffic/start", {"iface": iface},
                       callback=lambda d: self._set_capturing(True))

    def _on_stop(self) -> None:
        self._api.post("/api/traffic/stop", callback=lambda d: self._set_capturing(False))

    def _on_clear(self) -> None:
        self._api.post("/api/traffic/clear", callback=lambda d: self.refresh())

    def _set_capturing(self, capturing: bool) -> None:
        self._live_btn.setEnabled(not capturing)
        self._stop_btn.setEnabled(capturing)
        self._oneshot_btn.setEnabled(not capturing)
        if capturing:
            self._live_btn.setText("● En direct…")
        else:
            self._live_btn.setText("▶  Live")

    def _on_capture_result(self, data: dict) -> None:
        self._oneshot_btn.setEnabled(True)
        self._oneshot_btn.setText("📥  Capture 10s")
        self._populate_packets(data)

    def _on_packet_selected(self) -> None:
        rows = self._packet_table.selectedIndexes()
        if not rows:
            return
        row = rows[0].row()
        no_item = self._packet_table.item(row, 0)
        if not no_item:
            return
        packet_no = no_item.text()
        self._api.get(f"/api/traffic/packet/{packet_no}", callback=self._on_packet_detail)

    def _on_packet_detail(self, data: dict) -> None:
        layers = data.get("layers", {})
        hex_dump = data.get("hex_dump", "")

        detail_text = ""
        for layer, fields in layers.items():
            detail_text += f"\n--- {layer} ---\n"
            if isinstance(fields, dict):
                for k, v in fields.items():
                    detail_text += f"  {k}: {v}\n"
        self._detail_panel.setPlainText(detail_text)

        if hex_dump:
            self._hex_panel.setPlainText(hex_dump)
        else:
            self._hex_panel.clear()

    def _populate_packets(self, data: dict) -> None:
        packets = data.get("packets", data.get("results", []))
        self._packet_table.setRowCount(len(packets))
        for i, pkt in enumerate(packets):
            self._packet_table.setItem(i, 0, QTableWidgetItem(str(pkt.get("no", i + 1))))
            self._packet_table.setItem(i, 1, QTableWidgetItem(str(pkt.get("time", ""))[-12:]))
            self._packet_table.setItem(i, 2, QTableWidgetItem(pkt.get("src", "")))
            self._packet_table.setItem(i, 3, QTableWidgetItem(pkt.get("dst", "")))

            proto = pkt.get("protocol", pkt.get("proto", ""))
            proto_item = QTableWidgetItem(proto)
            color = PROTOCOL_COLORS.get(proto.upper(), "#6B7280")
            proto_item.setForeground(QColor(color))
            self._packet_table.setItem(i, 4, proto_item)

            self._packet_table.setItem(i, 5, QTableWidgetItem(str(pkt.get("length", ""))))
            self._packet_table.setItem(i, 6, QTableWidgetItem(str(pkt.get("info", ""))[:80]))

    def refresh(self) -> None:
        self._api.get("/api/traffic/packets?limit=100", callback=self._populate_packets)
