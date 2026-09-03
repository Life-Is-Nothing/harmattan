"""HARMATTAN About dialog."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTabWidget, QWidget, QTextEdit, QGroupBox,
)

from harmattan_gui.theme.manager import ThemeManager


class AboutDialog(QDialog):
    """About dialog showing version, author, preflight info."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("À propos de HARMATTAN")
        self.setFixedSize(500, 400)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Title
        title = QLabel("◆  HARMATTAN")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #0D9488;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Network Intelligence Suite · v3.22.0")
        subtitle.setStyleSheet("font-size: 14px; color: #94A3B8;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        layout.addSpacing(16)

        tabs = QTabWidget()

        # About tab
        about = QWidget()
        about_layout = QVBoxLayout(about)
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml("""
        <h3>HARMATTAN — Professional Network Intelligence Suite</h3>
        <p>Suite d'audit réseau, SOC lab, pentest éthique et IA cyber.</p>
        <ul>
            <li><b>Fonctionnalités</b> : ARP, nmap, topologie, CVE, trafic, OT, IPv6</li>
            <li><b>IA</b> : Analyse heuristique, scoring, mapping MITRE ATT&CK</li>
            <li><b>Exports</b> : PDF, DOCX, HTML, CSV, XLSX, STIX, GraphML</li>
            <li><b>Notifications</b> : Slack, Discord, Email, Syslog</li>
        </ul>
        <p><i>Usage strictement réservé à l'audit de réseaux autorisés.</i></p>
        <hr>
        <p><b>Version</b> : 3.22.0 Desktop</p>
        <p><b>Auteur</b> : Mohamed Adoungouss Ibrahim / NACF</p>
        <p><b>Licence</b> : Usage autorisé uniquement</p>
        """)
        about_layout.addWidget(about_text)
        tabs.addTab(about, "À propos")

        # Preflight tab
        preflight_tab = QWidget()
        pl_layout = QVBoxLayout(preflight_tab)
        self._preflight_text = QTextEdit()
        self._preflight_text.setReadOnly(True)
        pl_layout.addWidget(self._preflight_text)
        refresh_btn = QPushButton("🔄  Vérifier l'environnement")
        refresh_btn.clicked.connect(self._load_preflight)
        pl_layout.addWidget(refresh_btn)
        tabs.addTab(preflight_tab, "Environnement")

        # Credits tab
        credits = QWidget()
        credits_layout = QVBoxLayout(credits)
        credits_text = QTextEdit()
        credits_text.setReadOnly(True)
        credits_text.setHtml("""
        <h3>Technologies utilisées</h3>
        <ul>
            <li><b>Backend</b> : Python 3.12, Flask, SQLite, Scapy</li>
            <li><b>Desktop</b> : PyQt6, QtCharts</li>
            <li><b>IA</b> : scikit-learn (IsolationForest), Ollama (optionnel)</li>
            <li><b>Rapports</b> : ReportLab, python-docx, openpyxl</li>
        </ul>
        """)
        credits_layout.addWidget(credits_text)
        tabs.addTab(credits, "Crédits")

        layout.addWidget(tabs)

        layout.addSpacing(8)

        # Logo
        logo = QLabel("HARMATTAN · Network Intelligence · Liquid Glass · AI")
        logo.setStyleSheet("color: #64748B; font-size: 10px;")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo)

        # Close button
        close_btn = QPushButton("Fermer")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

    def _load_preflight(self) -> None:
        """Fetch and display preflight info."""
        from harmattan_gui.api.client import ApiClient

        api = ApiClient.instance()

        def _on_preflight(data: dict) -> None:
            import json
            self._preflight_text.setPlainText(
                json.dumps(data, indent=2, default=str, ensure_ascii=False)
            )

        api.get_preflight(callback=_on_preflight)
