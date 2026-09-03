"""Plugins view."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QFileDialog, QMessageBox,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient


class PluginsView(BaseView):
    TITLE = "Plugins"
    ICON = "🧩"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        ctrl_row = QHBoxLayout()
        self._refresh_btn = QPushButton("🔄  Rafraîchir")
        self._refresh_btn.clicked.connect(self.refresh)
        ctrl_row.addWidget(self._refresh_btn)
        self._install_btn = QPushButton("📦  Installer un plugin")
        self._install_btn.clicked.connect(self._on_install)
        ctrl_row.addWidget(self._install_btn)
        ctrl_row.addStretch()
        self._layout.addLayout(ctrl_row)

        group = QGroupBox("Plugins installés")
        table_layout = QVBoxLayout()
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(["Nom", "Version", "Description", "Auteur", "Statut"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        table_layout.addWidget(self._table)
        group.setLayout(table_layout)
        self._layout.addWidget(group)

        info_group = QGroupBox("Développement de plugins")
        info_layout = QVBoxLayout()
        info_layout.addWidget(QLabel(
            "Les plugins sont des modules Python dans ~/.harmattan/plugins/\n"
            "Héritez de PluginBase et implémentez les hooks :\n"
            "  • on_startup(app)\n"
            "  • on_scan_complete(scan_type, results)\n"
            "  • on_export(format, data)\n"
            "  • on_event(event_type, payload)\n"
            "  • on_shutdown()"
        ))
        info_group.setLayout(info_layout)
        self._layout.addWidget(info_group)

    def _on_install(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Sélectionner un plugin Python", "", "Python files (*.py)"
        )
        if file_path:
            import shutil
            import os
            plugins_dir = os.path.expanduser("~/.harmattan/plugins")
            os.makedirs(plugins_dir, exist_ok=True)
            dest = os.path.join(plugins_dir, os.path.basename(file_path))
            try:
                shutil.copy2(file_path, dest)
                QMessageBox.information(self, "Plugin installé",
                                        f"Plugin installé :\n{dest}")
                self.refresh()
            except Exception as e:
                QMessageBox.warning(self, "Erreur", f"Échec de l'installation :\n{e}")

    def refresh(self) -> None:
        self._api.get("/api/v1/plugins", callback=self._on_plugins)

    def _on_plugins(self, data: list) -> None:
        self._table.setRowCount(len(data))
        for i, p in enumerate(data):
            self._table.setItem(i, 0, QTableWidgetItem(p.get("name", "?")))
            self._table.setItem(i, 1, QTableWidgetItem(p.get("version", "?")))
            self._table.setItem(i, 2, QTableWidgetItem(p.get("description", "")[:60]))
            self._table.setItem(i, 3, QTableWidgetItem(p.get("author", "")))
            enabled = p.get("enabled", 0)
            self._table.setItem(i, 4, QTableWidgetItem("✓ Actif" if enabled else "✗ Désactivé"))
