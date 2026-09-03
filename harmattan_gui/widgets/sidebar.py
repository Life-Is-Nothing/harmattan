"""
HARMATTAN Desktop GUI — Sidebar Navigation.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QSpacerItem, QSizePolicy


NAV_ITEMS = [
    ("00", "SOC Dashboard", "📊"),
    ("01", "Découverte ARP", "📡"),
    ("02", "Scan Nmap", "🔍"),
    ("03", "Topologie", "🕸️"),
    ("04", "Attack Surface", "🎯"),
    ("05", "Vulnérabilités", "🔓"),
    ("06", "Trafic", "📦"),
    ("07", "Outils", "🛠️"),
    ("08", "Intel", "🧠"),
    ("09", "AI Analyst", "🤖"),
    ("10", "Export", "📤"),
    ("11", "Configuration", "⚙️"),
    ("12", "Notifications", "🔔"),
    ("13", "Plugins", "🧩"),
]


class SidebarButton(QPushButton):
    """A styled sidebar navigation button."""

    def __init__(self, number: str, label: str, icon: str = "",
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        text = f"{icon}  {label}" if icon else f"  {label}"
        self.setText(text)
        self.setProperty("navIndex", number)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(40)
        font = QFont("Segoe UI", 11)
        self.setFont(font)


class Sidebar(QWidget):
    """Sidebar navigation widget."""

    view_changed = pyqtSignal(int)  # view index

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._buttons: list[SidebarButton] = []
        self._current_index = 0
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 12, 8, 12)
        layout.setSpacing(2)

        # Brand header
        brand = QLabel("◆  HARMATTAN")
        brand.setStyleSheet("font-size: 16px; font-weight: bold; padding: 8px 12px 16px;")
        layout.addWidget(brand)

        # Separator
        sep = QLabel()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background: #475569; margin: 4px 8px;")
        layout.addWidget(sep)

        # Nav buttons
        for idx, (num, label, icon) in enumerate(NAV_ITEMS):
            btn = SidebarButton(num, label, icon)
            btn.clicked.connect(lambda checked, i=idx: self._on_click(i))
            layout.addWidget(btn)
            self._buttons.append(btn)

        layout.addStretch()

        # Version footer
        footer = QLabel("v3.22.0 · Desktop")
        footer.setStyleSheet("font-size: 10px; color: #64748B; padding: 8px;")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(footer)

        self.setFixedWidth(220)
        self.set_current(0)

    def _on_click(self, index: int) -> None:
        self.set_current(index)
        self.view_changed.emit(index)

    def set_current(self, index: int) -> None:
        """Highlight the active nav item."""
        self._current_index = index
        for i, btn in enumerate(self._buttons):
            btn.setChecked(i == index)
            if i == index:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #0D9488;
                        color: white;
                        border: none;
                        border-radius: 6px;
                        padding: 8px 12px;
                        text-align: left;
                    }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        color: #94A3B8;
                        border: none;
                        border-radius: 6px;
                        padding: 8px 12px;
                        text-align: left;
                    }
                    QPushButton:hover {
                        background-color: #334155;
                        color: #F1F5F9;
                    }
                """)
