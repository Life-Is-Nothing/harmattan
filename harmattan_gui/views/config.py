"""Configuration view."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QGroupBox,
    QTabWidget, QWidget,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.theme.manager import ThemeManager


class ConfigView(BaseView):
    TITLE = "Configuration"
    ICON = "⚙️"

    def __init__(self, parent=None):
        self._theme = ThemeManager.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        tabs = QTabWidget()

        # General tab
        general = QWidget()
        gl = QVBoxLayout(general)
        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("Thème:"))
        self._theme_btn = QPushButton("Basculer en Light" if self._theme.current == "dark" else "Basculer en Dark")
        self._theme_btn.clicked.connect(self._toggle_theme)
        theme_row.addWidget(self._theme_btn)
        theme_row.addStretch()
        gl.addLayout(theme_row)
        gl.addStretch()
        tabs.addTab(general, "Général")

        # Auth tab
        auth = QWidget()
        al = QVBoxLayout(auth)
        al.addWidget(QLabel("Token API et configuration d'authentification"))
        al.addStretch()
        tabs.addTab(auth, "Authentification")

        # Integrations tab
        integrations = QWidget()
        il = QVBoxLayout(integrations)
        il.addWidget(QLabel("Webhooks Slack / Discord / Email / Syslog"))
        il.addStretch()
        tabs.addTab(integrations, "Intégrations")

        self._layout.addWidget(tabs)

    def _toggle_theme(self) -> None:
        self._theme.toggle()
        self._theme_btn.setText(
            "Basculer en Light" if self._theme.current == "dark" else "Basculer en Dark"
        )

    def refresh(self) -> None:
        pass
