"""Export view — generate reports in multiple formats."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QGridLayout, QFileDialog, QMessageBox, QLineEdit,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient


EXPORT_FORMATS = [
    ("HTML", "/api/report.html", "text/html", ".html"),
    ("PDF", "/api/report.pdf", "application/pdf", ".pdf"),
    ("DOCX", "/api/report.docx", "application/vnd.openxmlformats", ".docx"),
    ("JSON", "/api/report.json", "application/json", ".json"),
    ("CSV", "/api/export/csv", "text/csv", ".csv"),
    ("XLSX", "/api/export/xlsx", "application/vnd.openxmlformats", ".xlsx"),
    ("Markdown", "/api/export/markdown", "text/markdown", ".md"),
    ("STIX 2.1", "/api/export/stix", "application/json", ".json"),
    ("GraphML", "/api/export/graphml", "application/xml", ".graphml"),
]


class ExportView(BaseView):
    TITLE = "Export & Rapports"
    ICON = "📤"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        # Format grid
        grid = QGridLayout()
        grid.setSpacing(8)
        for i, (name, endpoint, mime, ext) in enumerate(EXPORT_FORMATS):
            btn = QPushButton(f"📄  {name}")
            btn.setMinimumHeight(48)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, e=endpoint, f=name: self._on_export(e, f))
            grid.addWidget(btn, i // 3, i % 3)
        self._layout.addLayout(grid)

        # Export history
        hist_group = QGroupBox("Historique des exports")
        hist_layout = QVBoxLayout()
        self._history_table = QTableWidget()
        self._history_table.setColumnCount(4)
        self._history_table.setHorizontalHeaderLabels(["Format", "Date", "Taille", "Fichier"])
        self._history_table.horizontalHeader().setStretchLastSection(True)
        hist_layout.addWidget(self._history_table)
        self._refresh_hist_btn = QPushButton("🔄  Rafraîchir historique")
        self._refresh_hist_btn.clicked.connect(self._load_history)
        hist_layout.addWidget(self._refresh_hist_btn)
        hist_group.setLayout(hist_layout)
        self._layout.addWidget(hist_group)

    def _on_export(self, endpoint: str, fmt: str) -> None:
        file_path, _ = QFileDialog.getSaveFileName(self, f"Exporter en {fmt}", f"harmattan_report{endpoint.split('.')[-1]}")
        if not file_path:
            return

        import urllib.request

        try:
            from harmattan_gui.api import endpoints as E
            url = f"{E.BASE_URL}{endpoint}"
            import os
            token = os.environ.get("HARMATTAN_TOKEN", "")
            req = urllib.request.Request(url)
            if token:
                req.add_header("X-Harmattan-Token", token)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                with open(file_path, "wb") as f:
                    f.write(data)

            QMessageBox.information(self, "Export réussi",
                                    f"Fichier exporté :\n{file_path}")
        except Exception as e:
            QMessageBox.warning(self, "Erreur d'export",
                                f"Échec de l'export {fmt} :\n{e}")

        self._load_history()

    def _load_history(self) -> None:
        self._api.get("/api/v1/exports", callback=self._on_history)

    def _on_history(self, data: list) -> None:
        self._history_table.setRowCount(len(data))
        for i, exp in enumerate(data):
            self._history_table.setItem(i, 0, QTableWidgetItem(exp.get("format", "")))
            self._history_table.setItem(i, 1, QTableWidgetItem(str(exp.get("created", ""))[-19:]))
            size = exp.get("size", 0)
            size_str = f"{size / 1024:.1f} KB" if size else "—"
            self._history_table.setItem(i, 2, QTableWidgetItem(size_str))
            self._history_table.setItem(i, 3, QTableWidgetItem(exp.get("file_path", "")[:50]))

    def refresh(self) -> None:
        self._load_history()
