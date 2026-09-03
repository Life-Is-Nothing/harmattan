"""
HARMATTAN Desktop GUI — Theme Manager.
Manages dark/light themes with QSS stylesheets and palette colors.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QPalette, QColor
from PyQt6.QtWidgets import QApplication


class ThemeManager(QObject):
    """Singleton theme manager for the desktop GUI."""

    theme_changed = pyqtSignal(str)  # "dark" | "light"

    _instance: Optional["ThemeManager"] = None

    DARK_PALETTE = {
        "bg_primary": "#0F172A",
        "bg_secondary": "#1E293B",
        "bg_surface": "#334155",
        "text_primary": "#F1F5F9",
        "text_secondary": "#94A3B8",
        "text_muted": "#64748B",
        "accent": "#0D9488",
        "accent_hover": "#0F766E",
        "danger": "#DC2626",
        "warning": "#EA580C",
        "success": "#16A34A",
        "info": "#2563EB",
        "border": "#475569",
        "bg_input": "#1E293B",
        "bg_hover": "#334155",
    }

    LIGHT_PALETTE = {
        "bg_primary": "#F8FAFC",
        "bg_secondary": "#FFFFFF",
        "bg_surface": "#F1F5F9",
        "text_primary": "#0F172A",
        "text_secondary": "#475569",
        "text_muted": "#94A3B8",
        "accent": "#0D9488",
        "accent_hover": "#0F766E",
        "danger": "#DC2626",
        "warning": "#EA580C",
        "success": "#16A34A",
        "info": "#2563EB",
        "border": "#E2E8F0",
        "bg_input": "#FFFFFF",
        "bg_hover": "#F1F5F9",
    }

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._current = "dark"
        self._palettes = {
            "dark": self.DARK_PALETTE,
            "light": self.LIGHT_PALETTE,
        }

    @classmethod
    def instance(cls, parent: Optional[QObject] = None) -> "ThemeManager":
        if cls._instance is None:
            cls._instance = cls(parent)
        return cls._instance

    @property
    def current(self) -> str:
        return self._current

    @property
    def palette(self) -> dict:
        return self._palettes[self._current]

    def toggle(self) -> None:
        """Switch between dark and light."""
        new = "light" if self._current == "dark" else "dark"
        self.set_theme(new)

    def set_theme(self, theme: str) -> None:
        """Apply a theme by name ('dark' or 'light')."""
        if theme not in self._palettes:
            return
        self._current = theme
        self._apply_qpalette()
        self._apply_stylesheet()
        self.theme_changed.emit(theme)

    def _apply_qpalette(self) -> None:
        """Set the application QPalette."""
        p = self._palettes[self._current]
        qp = QPalette()

        qp.setColor(QPalette.ColorRole.Window, QColor(p["bg_primary"]))
        qp.setColor(QPalette.ColorRole.WindowText, QColor(p["text_primary"]))
        qp.setColor(QPalette.ColorRole.Base, QColor(p["bg_secondary"]))
        qp.setColor(QPalette.ColorRole.AlternateBase, QColor(p["bg_surface"]))
        qp.setColor(QPalette.ColorRole.ToolTipBase, QColor(p["bg_surface"]))
        qp.setColor(QPalette.ColorRole.ToolTipText, QColor(p["text_primary"]))
        qp.setColor(QPalette.ColorRole.Text, QColor(p["text_primary"]))
        qp.setColor(QPalette.ColorRole.Button, QColor(p["bg_secondary"]))
        qp.setColor(QPalette.ColorRole.ButtonText, QColor(p["text_primary"]))
        qp.setColor(QPalette.ColorRole.BrightText, QColor("white"))
        qp.setColor(QPalette.ColorRole.Link, QColor(p["accent"]))
        qp.setColor(QPalette.ColorRole.Highlight, QColor(p["accent"]))
        qp.setColor(QPalette.ColorRole.HighlightedText, QColor("white"))

        QApplication.instance().setPalette(qp)

    def _apply_stylesheet(self) -> None:
        """Load and apply QSS stylesheet."""
        p = self._palettes[self._current]
        app = QApplication.instance()

        qss = f"""
        /* HARMATTAN {self._current.upper()} THEME */
        QMainWindow {{ background-color: {p["bg_primary"]}; }}
        QWidget {{ background-color: transparent; color: {p["text_primary"]}; font-family: 'Segoe UI', system-ui, sans-serif; }}
        QLabel {{ color: {p["text_primary"]}; background: transparent; }}
        QPushButton {{
            background-color: {p["bg_surface"]};
            color: {p["text_primary"]};
            border: 1px solid {p["border"]};
            border-radius: 6px;
            padding: 6px 16px;
            font-size: 13px;
        }}
        QPushButton:hover {{ background-color: {p["accent"]}; color: white; border-color: {p["accent"]}; }}
        QPushButton:pressed {{ background-color: {p["accent_hover"]}; }}
        QPushButton:disabled {{ background-color: {p["bg_surface"]}; color: {p["text_muted"]}; }}
        QLineEdit, QSpinBox, QComboBox {{
            background-color: {p["bg_input"]};
            color: {p["text_primary"]};
            border: 1px solid {p["border"]};
            border-radius: 6px;
            padding: 6px 10px;
            font-size: 13px;
        }}
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
            border-color: {p["accent"]};
        }}
        QComboBox::drop-down {{
            border: none;
            width: 24px;
        }}
        QComboBox QAbstractItemView {{
            background-color: {p["bg_secondary"]};
            color: {p["text_primary"]};
            selection-background-color: {p["accent"]};
        }}
        QTextEdit, QPlainTextEdit {{
            background-color: {p["bg_input"]};
            color: {p["text_primary"]};
            border: 1px solid {p["border"]};
            border-radius: 6px;
            padding: 6px;
            font-family: 'Cascadia Code', 'Fira Code', monospace;
            font-size: 12px;
        }}
        QTableView {{
            background-color: {p["bg_secondary"]};
            color: {p["text_primary"]};
            border: 1px solid {p["border"]};
            border-radius: 6px;
            gridline-color: {p["border"]};
            selection-background-color: {p["accent"]};
            selection-color: white;
            font-size: 12px;
        }}
        QTableView::item {{ padding: 4px 8px; }}
        QTableView::item:hover {{ background-color: {p["bg_hover"]}; }}
        QHeaderView::section {{
            background-color: {p["bg_surface"]};
            color: {p["text_secondary"]};
            padding: 6px 8px;
            border: none;
            border-bottom: 1px solid {p["border"]};
            font-weight: bold;
            font-size: 11px;
            text-transform: uppercase;
        }}
        QTreeView {{
            background-color: {p["bg_secondary"]};
            color: {p["text_primary"]};
            border: 1px solid {p["border"]};
            border-radius: 6px;
        }}
        QTreeView::item:hover {{ background-color: {p["bg_hover"]}; }}
        QTreeView::item:selected {{ background-color: {p["accent"]}; color: white; }}
        QScrollBar:vertical {{
            background: {p["bg_primary"]};
            width: 10px;
            border-radius: 5px;
        }}
        QScrollBar::handle:vertical {{
            background: {p["border"]};
            border-radius: 5px;
            min-height: 30px;
        }}
        QScrollBar::handle:vertical:hover {{ background: {p["accent"]}; }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
        QTabWidget::pane {{
            border: 1px solid {p["border"]};
            border-radius: 6px;
            background-color: {p["bg_secondary"]};
        }}
        QTabBar::tab {{
            background-color: {p["bg_surface"]};
            color: {p["text_secondary"]};
            padding: 8px 16px;
            border: 1px solid {p["border"]};
            border-bottom: none;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            margin-right: 2px;
        }}
        QTabBar::tab:selected {{
            background-color: {p["bg_secondary"]};
            color: {p["accent"]};
            font-weight: bold;
        }}
        QTabBar::tab:hover {{ color: {p["text_primary"]}; }}
        QGroupBox {{
            border: 1px solid {p["border"]};
            border-radius: 8px;
            margin-top: 12px;
            padding: 16px 12px 12px;
            font-weight: bold;
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
            color: {p["accent"]};
        }}
        QProgressBar {{
            background-color: {p["bg_surface"]};
            border: none;
            border-radius: 4px;
            height: 8px;
            text-align: center;
            font-size: 10px;
        }}
        QProgressBar::chunk {{
            background-color: {p["accent"]};
            border-radius: 4px;
        }}
        QStatusBar {{
            background-color: {p["bg_secondary"]};
            color: {p["text_muted"]};
            border-top: 1px solid {p["border"]};
            font-size: 11px;
        }}
        QMenu {{
            background-color: {p["bg_secondary"]};
            color: {p["text_primary"]};
            border: 1px solid {p["border"]};
            border-radius: 6px;
            padding: 4px;
        }}
        QMenu::item {{ padding: 6px 24px; border-radius: 4px; }}
        QMenu::item:selected {{ background-color: {p["accent"]}; color: white; }}
        QMenu::separator {{ height: 1px; background: {p["border"]}; margin: 4px 8px; }}
        QToolTip {{
            background-color: {p["bg_surface"]};
            color: {p["text_primary"]};
            border: 1px solid {p["border"]};
            border-radius: 4px;
            padding: 4px 8px;
            font-size: 12px;
        }}
        QCheckBox {{
            spacing: 8px;
            color: {p["text_primary"]};
        }}
        QCheckBox::indicator {{
            width: 16px; height: 16px;
            border: 2px solid {p["border"]};
            border-radius: 3px;
            background: {p["bg_input"]};
        }}
        QCheckBox::indicator:checked {{
            background: {p["accent"]};
            border-color: {p["accent"]};
        }}
        QSplitter::handle {{
            background: {p["border"]};
            width: 1px;
        }}
        """
        app.setStyleSheet(qss)
