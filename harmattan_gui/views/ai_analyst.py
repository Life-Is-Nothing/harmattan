"""AI Analyst view."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QGroupBox, QPlainTextEdit,
)

from harmattan_gui.views.base_view import BaseView
from harmattan_gui.api.client import ApiClient


class AiAnalystView(BaseView):
    TITLE = "AI Analyst"
    ICON = "🤖"

    def __init__(self, parent=None):
        self._api = ApiClient.instance()
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        ctrl_row = QHBoxLayout()
        self._analyze_btn = QPushButton("🧠  Analyser le réseau")
        self._analyze_btn.clicked.connect(self._on_analyze)
        ctrl_row.addWidget(self._analyze_btn)
        self._status_label = QLabel("Prêt")
        self._status_label.setStyleSheet("color: #64748B;")
        ctrl_row.addWidget(self._status_label)
        ctrl_row.addStretch()
        self._layout.addLayout(ctrl_row)

        # Results tree
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Section", "Contenu"])
        self._tree.header().setStretchLastSection(True)
        self._tree.setAlternatingRowColors(True)
        self._layout.addWidget(self._tree, 2)

        # Risk gauge and recommendations
        bottom_row = QHBoxLayout()
        gauge_group = QGroupBox("Score de risque")
        gauge_layout = QVBoxLayout()
        self._risk_label = QLabel("N/A")
        self._risk_label.setStyleSheet("font-size: 36px; font-weight: bold; color: #0D9488;")
        self._risk_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gauge_layout.addWidget(self._risk_label)
        self._grade_label = QLabel("Grade: —")
        self._grade_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gauge_layout.addWidget(self._grade_label)
        gauge_group.setLayout(gauge_layout)
        bottom_row.addWidget(gauge_group)

        rec_group = QGroupBox("Recommandations prioritaires")
        rec_layout = QVBoxLayout()
        self._rec_text = QPlainTextEdit()
        self._rec_text.setReadOnly(True)
        self._rec_text.setMaximumBlockCount(100)
        rec_layout.addWidget(self._rec_text)
        rec_group.setLayout(rec_layout)
        bottom_row.addWidget(rec_group, 2)
        self._layout.addLayout(bottom_row)

    def _on_analyze(self) -> None:
        self._analyze_btn.setEnabled(False)
        self._analyze_btn.setText("Analyse en cours…")
        self._status_label.setText("Analyse IA en cours…")
        self._api.get_ai_analysis(callback=self._on_result)

    def _on_result(self, data: dict) -> None:
        self._analyze_btn.setEnabled(True)
        self._analyze_btn.setText("🧠  Analyser le réseau")
        self._status_label.setText("Analyse terminée")

        self._tree.clear()

        # Summary
        summary = data.get("summary", "")
        root = QTreeWidgetItem(self._tree, ["Résumé", str(summary)[:200]])
        self._tree.addTopLevelItem(root)

        # Risk score
        risk = data.get("risk_score", data.get("score", {}))
        if isinstance(risk, dict):
            score = risk.get("score", risk.get("total", "N/A"))
            grade = risk.get("grade", risk.get("level", "N/A"))
            self._risk_label.setText(str(score))
            self._grade_label.setText(f"Grade: {grade}")
        elif isinstance(risk, (int, float)):
            self._risk_label.setText(str(risk))

        # Attack paths
        paths = data.get("attack_paths", data.get("paths", []))
        if paths:
            paths_item = QTreeWidgetItem(self._tree, ["Chemins d'attaque", f"{len(paths)} identifiés"])
            for p in paths[:10]:
                desc = p.get("description", p.get("path", str(p)[:100]))
                QTreeWidgetItem(paths_item, ["", desc])
            self._tree.addTopLevelItem(paths_item)

        # Insecure services
        insecure = data.get("insecure_services", data.get("exposures", []))
        if insecure:
            svc_item = QTreeWidgetItem(self._tree, ["Services à risque", f"{len(insecure)} trouvés"])
            for s in insecure[:15]:
                host = s.get("host", s.get("ip", ""))
                port = s.get("port", "")
                svc = s.get("service", "")
                QTreeWidgetItem(svc_item, ["", f"{host}:{port} — {svc}"])
            self._tree.addTopLevelItem(svc_item)

        # Recommendations
        recs = data.get("recommendations", data.get("remediation", []))
        if recs:
            rec_item = QTreeWidgetItem(self._tree, ["Recommandations", f"{len(recs)} actions"])
            for r in recs[:20]:
                text = r.get("text", r.get("action", r.get("recommendation", str(r)[:100])))
                QTreeWidgetItem(rec_item, ["", text])
            self._tree.addTopLevelItem(rec_item)

            # Also show in text panel
            rec_text = "\n".join(f"• {r.get('text', r.get('action', r.get('recommendation', str(r)[:100])))}"
                                 for r in recs[:20])
            self._rec_text.setPlainText(rec_text)

        # Host details
        hosts = data.get("hosts", data.get("host_analyses", []))
        if hosts:
            host_item = QTreeWidgetItem(self._tree, ["Analyses par hôte", f"{len(hosts)} hôtes"])
            for h in hosts[:20]:
                ip = h.get("ip", h.get("host", ""))
                risk_lvl = h.get("risk", h.get("severity", ""))
                QTreeWidgetItem(host_item, ["", f"{ip} — Risque: {risk_lvl}"])
            self._tree.addTopLevelItem(host_item)

        self._tree.expandAll()

    def refresh(self) -> None:
        pass
