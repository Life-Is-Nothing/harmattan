"""Attack Surface view."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox, QGridLayout,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient
from harmattan_gui.theme.colors import SEVERITY_COLORS


class AttackSurfaceView(BaseView):
    TITLE = "Attack Surface"
    ICON = "🎯"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        # Controls
        ctrl_row = QHBoxLayout()
        self._refresh_btn = QPushButton("🔄  Analyser")
        self._refresh_btn.clicked.connect(self.refresh)
        ctrl_row.addWidget(self._refresh_btn)
        ctrl_row.addStretch()
        self._layout.addLayout(ctrl_row)

        # Stats row
        stats_grid = QGridLayout()
        stats_grid.setSpacing(12)
        self._total_label = QLabel("Total: —")
        self._critical_label = QLabel("Critique: —")
        self._high_label = QLabel("Haute: —")
        self._medium_label = QLabel("Moyenne: —")
        self._grade_label = QLabel("Grade: —")
        for lbl in [self._total_label, self._critical_label, self._high_label,
                     self._medium_label, self._grade_label]:
            lbl.setStyleSheet("font-size: 16px; font-weight: bold; padding: 8px;")
        stats_grid.addWidget(self._total_label, 0, 0)
        stats_grid.addWidget(self._critical_label, 0, 1)
        stats_grid.addWidget(self._high_label, 0, 2)
        stats_grid.addWidget(self._medium_label, 0, 3)
        stats_grid.addWidget(self._grade_label, 0, 4)
        self._layout.addLayout(stats_grid)

        # Exposures table
        group = QGroupBox("Expositions")
        table_layout = QVBoxLayout()
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(["Hôte", "Port", "Service", "Risque", "Détail"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        table_layout.addWidget(self._table)
        group.setLayout(table_layout)
        self._layout.addWidget(group)

        # Recommendations
        rec_group = QGroupBox("Recommandations")
        rec_layout = QVBoxLayout()
        self._rec_label = QLabel("Lancez une analyse pour voir les recommandations.")
        self._rec_label.setWordWrap(True)
        rec_layout.addWidget(self._rec_label)
        rec_group.setLayout(rec_layout)
        self._layout.addWidget(rec_group)

    def refresh(self) -> None:
        self._refresh_btn.setEnabled(False)
        self._refresh_btn.setText("Analyse en cours…")
        self._api.get_attack_surface(callback=self._on_result)

    def _on_result(self, data: dict) -> None:
        self._refresh_btn.setEnabled(True)
        self._refresh_btn.setText("🔄  Analyser")

        exposures = data.get("exposures", data.get("findings", []))
        grade = data.get("grade", data.get("score", "N/A"))
        stats = data.get("stats", {})

        self._total_label.setText(f"Total: {len(exposures)}")
        critical = sum(1 for e in exposures if e.get("risk", e.get("severity", "")).lower() == "critique")
        high = sum(1 for e in exposures if e.get("risk", e.get("severity", "")).lower() == "haute")
        medium = sum(1 for e in exposures if e.get("risk", e.get("severity", "")).lower() == "moyenne")
        self._critical_label.setText(f"Critique: {critical}")
        self._high_label.setText(f"Haute: {high}")
        self._medium_label.setText(f"Moyenne: {medium}")
        self._grade_label.setText(f"Grade: {grade}")

        self._table.setRowCount(len(exposures))
        for i, exp in enumerate(exposures):
            self._table.setItem(i, 0, QTableWidgetItem(exp.get("host", exp.get("ip", ""))))
            self._table.setItem(i, 1, QTableWidgetItem(str(exp.get("port", ""))))
            self._table.setItem(i, 2, QTableWidgetItem(str(exp.get("service", ""))))
            risk = exp.get("risk", exp.get("severity", ""))
            risk_item = QTableWidgetItem(risk)
            color = SEVERITY_COLORS.get(risk.lower(), "#6B7280")
            risk_item.setForeground(QColor(color))
            self._table.setItem(i, 3, risk_item)
            self._table.setItem(i, 4, QTableWidgetItem(str(exp.get("detail", ""))[:100]))

        recs = data.get("recommendations", [])
        if recs:
            self._rec_label.setText("\n".join(f"• {r}" for r in recs[:10]))
