"""
HARMATTAN Desktop GUI — Base View.
All views inherit from this class for consistent behavior.
"""
from __future__ import annotations

from typing import Any, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


class BaseView(QWidget):
    """Base class for all desktop views."""

    TITLE = "View"
    ICON = ""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(24, 24, 24, 24)
        self._layout.setSpacing(16)
        self._loading = False
        self._error_widget: Optional[QLabel] = None
        self._setup_header()

    def _setup_header(self) -> None:
        """Create the view header with title."""
        header = QLabel(f"{self.ICON}  {self.TITLE}")
        header.setStyleSheet("font-size: 22px; font-weight: bold; padding-bottom: 8px;")
        self._layout.addWidget(header)

    def show_error(self, message: str) -> None:
        """Display an error message within the view."""
        if self._error_widget:
            self._error_widget.setText(f"❌ {message}")
            self._error_widget.show()
            return
        self._error_widget = QLabel(f"❌ {message}")
        self._error_widget.setStyleSheet(
            "color: #DC2626; background: #1E293B; padding: 16px; "
            "border: 1px solid #DC2626; border-radius: 8px; font-size: 13px;"
        )
        self._error_widget.setWordWrap(True)
        self._layout.insertWidget(1, self._error_widget)

    def clear_error(self) -> None:
        if self._error_widget:
            self._error_widget.hide()

    def refresh(self) -> None:
        """Refresh view data (override in subclasses)."""
        pass

    def on_activate(self) -> None:
        """Called when view becomes active."""
        pass
