"""Tools view — interactive network tools."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QPlainTextEdit, QGroupBox, QGridLayout,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient
from harmattan_gui.theme.colors import SEVERITY_COLORS


class ToolButton(QPushButton):
    """A styled tool button."""

    def __init__(self, label: str, tool: str, parent=None):
        super().__init__(label, parent)
        self._tool = tool
        self.setMinimumHeight(40)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("""
            QPushButton {
                background: #1E293B; border: 1px solid #334155;
                border-radius: 6px; padding: 8px 16px;
                font-size: 12px; text-align: left;
            }
            QPushButton:hover { background: #0D9488; color: white; border-color: #0D9488; }
        """)

    @property
    def tool(self) -> str:
        return self._tool


class ToolsView(BaseView):
    TITLE = "Outils Réseau"
    ICON = "🛠️"

    TOOLS = [
        ("📌  Ping", "tools/ping"),
        ("🔄  Traceroute", "tools/traceroute"),
        ("🏷️  Banner Grab", "tools/banner"),
        ("🌐  DNS Lookup", "tools/dns"),
        ("🔒  TLS Inspect", "tools/tls"),
        ("🔍  Port Check", "tools/port-check"),
        ("📋  Port Scan", "tools/port-scan"),
        ("👤  WHOIS", "tools/whois"),
        ("🏭  MAC OUI", "tools/mac"),
        ("🔑  SSH Keyscan", "tools/ssh-keyscan"),
    ]

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        # Input row
        input_row = QHBoxLayout()
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("Cible (IP, domaine ou URL)")
        input_row.addWidget(QLabel("Target:"))
        input_row.addWidget(self._target_input, 2)
        self._port_input = QLineEdit()
        self._port_input.setPlaceholderText("Port (optionnel)")
        self._port_input.setMaximumWidth(100)
        input_row.addWidget(QLabel("Port:"))
        input_row.addWidget(self._port_input)
        self._extra_input = QLineEdit()
        self._extra_input.setPlaceholderText("Arguments supplémentaires")
        input_row.addWidget(self._extra_input, 1)
        self._layout.addLayout(input_row)

        # Tool buttons grid
        grid = QGridLayout()
        grid.setSpacing(8)
        for i, (label, tool) in enumerate(self.TOOLS):
            btn = ToolButton(label, tool)
            btn.clicked.connect(lambda checked, t=tool: self._run_tool(t))
            grid.addWidget(btn, i // 2, i % 2)
        self._layout.addLayout(grid)

        # Results
        results_group = QGroupBox("Résultats")
        results_layout = QVBoxLayout()
        self._results = QPlainTextEdit()
        self._results.setReadOnly(True)
        self._results.setMaximumBlockCount(500)
        self._results.setPlaceholderText("Les résultats des outils s'afficheront ici…")
        results_layout.addWidget(self._results)
        self._clear_btn = QPushButton("🗑  Effacer")
        self._clear_btn.clicked.connect(self._results.clear)
        results_layout.addWidget(self._clear_btn)
        results_group.setLayout(results_layout)
        self._layout.addWidget(results_group, 1)

    def _run_tool(self, tool_path: str) -> None:
        target = self._target_input.text().strip()
        port = self._port_input.text().strip()
        extras = self._extra_input.text().strip()

        data = {"target": target}
        if port:
            try:
                data["port"] = int(port)
            except ValueError:
                data["port"] = port
        if extras:
            try:
                import shlex
                data["extra"] = shlex.split(extras) if " " in extras else extras
            except Exception:
                data["extra"] = extras

        self._results.appendPlainText(f"\n▶ {tool_path} {target} {'-p ' + port if port else ''}")
        self._api.post(f"/api/{tool_path}", data, callback=self._on_result,
                       errback=lambda e: self._results.appendPlainText(f"❌ Erreur: {e}"))

    def _on_result(self, data: dict) -> None:
        output = data.get("output", data.get("result", data.get("message", str(data)[:500])))
        self._results.appendPlainText(str(output))

    def refresh(self) -> None:
        pass
