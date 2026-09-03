#!/usr/bin/env python3
"""
HARMATTAN Desktop GUI — Application Entry Point.
"""
from __future__ import annotations

import sys
import os

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication


def main() -> int:
    """Launch the HARMATTAN Desktop GUI."""
    # High-DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("HARMATTAN")
    app.setOrganizationName("HARMATTAN")
    app.setDesktopFileName("harmattan-desktop")

    # Apply dark theme first
    from harmattan_gui.theme.manager import ThemeManager
    theme = ThemeManager.instance()
    theme.set_theme("dark")

    # Create and show main window (backend starts automatically)
    from harmattan_gui.main_window import MainWindow
    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
