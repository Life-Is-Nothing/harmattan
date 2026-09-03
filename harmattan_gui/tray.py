"""
HARMATTAN Desktop GUI — System Tray Icon.
"""
from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QIcon, QPixmap, QPainter, QColor, QFont
from PyQt6.QtWidgets import QSystemTrayIcon, QMenu


class TrayIcon(QSystemTrayIcon):
    """System tray icon with status indicator and context menu."""

    show_requested = pyqtSignal()
    quit_requested = pyqtSignal()
    scan_arp_requested = pyqtSignal()
    scan_nmap_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._status = "disconnected"  # disconnected | connected | scanning | error
        self._setup_icon()
        self._setup_menu()
        self.activated.connect(self._on_activated)
        self.show()

    def _setup_icon(self) -> None:
        """Create tray icon programmatically."""
        pixmap = QPixmap(24, 24)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QColor("#0D9488"))  # cyan
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(2, 2, 20, 20, 4, 4)
        painter.setPen(QColor("white"))
        font = QFont("monospace", 10, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(4, 18, "H")
        painter.end()
        self.setIcon(QIcon(pixmap))
        self._pixmap = pixmap

    def _setup_menu(self) -> None:
        menu = QMenu()
        self._show_action = menu.addAction("🪟 Afficher")
        self._show_action.triggered.connect(self.show_requested.emit)
        menu.addSeparator()
        scan_arp = menu.addAction("📡 Scan ARP")
        scan_arp.triggered.connect(self.scan_arp_requested.emit)
        scan_nmap = menu.addAction("🔍 Scan Nmap")
        scan_nmap.triggered.connect(self.scan_nmap_requested.emit)
        menu.addSeparator()
        quit_action = menu.addAction("❌ Quitter")
        quit_action.triggered.connect(self.quit_requested.emit)
        self.setContextMenu(menu)

    def set_status(self, status: str) -> None:
        """Update tray icon color based on status."""
        self._status = status
        colors = {
            "disconnected": "#6B7280",
            "connected": "#0D9488",
            "scanning": "#EA580C",
            "error": "#DC2626",
        }
        color = colors.get(status, "#6B7280")
        painter = QPainter(self._pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QColor(color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(2, 2, 20, 20, 4, 4)
        painter.setPen(QColor("white"))
        font = QFont("monospace", 10, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(4, 18, "H")
        painter.end()
        self.setIcon(QIcon(self._pixmap))

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_requested.emit()
