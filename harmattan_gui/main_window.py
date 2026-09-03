"""
HARMATTAN Desktop GUI — Main Window.
Central orchestrator: sidebar navigation, stacked views, system tray, backend lifecycle.
"""
from __future__ import annotations

from typing import Any, Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QStackedWidget,
    QStatusBar, QLabel, QApplication,
)

from harmattan_gui.widgets.sidebar import Sidebar
from harmattan_gui.backend import BackendProcess
from harmattan_gui.tray import TrayIcon
from harmattan_gui.api.client import ApiClient
from harmattan_gui.theme.manager import ThemeManager

# Views
from harmattan_gui.views.soc_dashboard import SocDashboardView
from harmattan_gui.views.arp_scan import ArpScanView
from harmattan_gui.views.nmap_scan import NmapScanView
from harmattan_gui.views.topology import TopologyView
from harmattan_gui.views.attack_surface import AttackSurfaceView
from harmattan_gui.views.vulnerabilities import VulnerabilitiesView
from harmattan_gui.views.traffic import TrafficView
from harmattan_gui.views.tools import ToolsView
from harmattan_gui.views.intel import IntelView
from harmattan_gui.views.ai_analyst import AiAnalystView
from harmattan_gui.views.export import ExportView
from harmattan_gui.views.config import ConfigView
from harmattan_gui.views.notifications import NotificationsView
from harmattan_gui.views.plugins import PluginsView

# Workers
from harmattan_gui.workers.sse_worker import SseWorker
from harmattan_gui.workers.job_poller import JobPoller


VIEW_CLASSES = [
    SocDashboardView,
    ArpScanView,
    NmapScanView,
    TopologyView,
    AttackSurfaceView,
    VulnerabilitiesView,
    TrafficView,
    ToolsView,
    IntelView,
    AiAnalystView,
    ExportView,
    ConfigView,
    NotificationsView,
    PluginsView,
]


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self._api = ApiClient.instance(self)
        self._theme = ThemeManager.instance(self)
        self._backend = BackendProcess(self)
        self._tray: Optional[TrayIcon] = None
        self._sse_worker: Optional[SseWorker] = None
        self._job_poller: Optional[JobPoller] = None
        self._views: list = []
        self._views_stack: Optional[QStackedWidget] = None

        self._setup_window()
        self._setup_ui()
        self._setup_backend()

    def _setup_window(self) -> None:
        """Configure the main window."""
        self.setWindowTitle("HARMATTAN — Network Intelligence Suite")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)

        # Menu bar
        menubar = self.menuBar()
        help_menu = menubar.addMenu("&Aide")
        about_action = help_menu.addAction("À propos de HARMATTAN")
        about_action.triggered.connect(self._show_about)
        about_action.setShortcut("Ctrl+H")
        theme_action = help_menu.addAction("Basculer thème (Dark/Light)")
        theme_action.triggered.connect(self._toggle_theme)
        theme_action.setShortcut("Ctrl+T")
        help_menu.addSeparator()
        quit_action = help_menu.addAction("Quitter")
        quit_action.triggered.connect(self._quit)
        quit_action.setShortcut("Ctrl+Q")

    def _show_about(self) -> None:
        from harmattan_gui.dialogs.about_dialog import AboutDialog
        dlg = AboutDialog(self)
        dlg.exec()

    def _toggle_theme(self) -> None:
        self._theme.toggle()

    def _setup_ui(self) -> None:
        """Build the main UI layout."""
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Sidebar
        self._sidebar = Sidebar()
        self._sidebar.view_changed.connect(self._on_view_changed)
        layout.addWidget(self._sidebar)

        # View stack
        self._views_stack = QStackedWidget()
        for ViewClass in VIEW_CLASSES:
            view = ViewClass()
            self._views_stack.addWidget(view)
            self._views.append(view)
        layout.addWidget(self._views_stack, 1)

        # Status bar
        status_bar = QStatusBar()
        self._status_label = QLabel("Initialisation…")
        status_bar.addWidget(self._status_label)
        self._backend_status = QLabel("Backend: déconnecté")
        status_bar.addPermanentWidget(self._backend_status)
        self.setStatusBar(status_bar)

    def _setup_backend(self) -> None:
        """Connect backend signals and start it."""
        self._backend.started.connect(self._on_backend_started)
        self._backend.stopped.connect(self._on_backend_stopped)
        self._backend.health_ok.connect(self._on_health_ok)
        self._backend.health_fail.connect(self._on_health_fail)
        self._backend.error.connect(self._on_backend_error)

        self._backend.start()

    def _on_backend_started(self) -> None:
        """Backend is ready — initialize UI state."""
        self._status_label.setText("Prêt")
        self._backend_status.setText("Backend: ✓ connecté")
        self._update_tray_status("connected")

        # Start SSE worker
        self._sse_worker = SseWorker(self)
        self._sse_worker.event_received.connect(self._on_sse_event)
        self._sse_worker.start()

        # Start job poller
        self._job_poller = JobPoller(self)
        self._job_poller.jobs_updated.connect(self._on_jobs_updated)
        self._job_poller.start()

        # Setup tray
        self._tray = TrayIcon(self)
        self._tray.show_requested.connect(self.show)
        self._tray.quit_requested.connect(self._quit)
        self._tray.show()

        # Refresh first view
        if self._views:
            self._views[0].refresh()

    def _on_backend_stopped(self, exit_code: int) -> None:
        self._backend_status.setText(f"Backend: arrêté (code {exit_code})")
        self._update_tray_status("disconnected")

    def _on_health_ok(self) -> None:
        self._backend_status.setText("Backend: ✓ sain")
        self._update_tray_status("connected")

    def _on_health_fail(self, msg: str) -> None:
        self._backend_status.setText(f"Backend: ✗ {msg}")
        self._update_tray_status("error")

    def _on_backend_error(self, msg: str) -> None:
        self._backend_status.setText(f"Backend: ✗ {msg}")
        self._update_tray_status("error")

    def _on_view_changed(self, index: int) -> None:
        """Switch active view."""
        if 0 <= index < len(self._views):
            self._views_stack.setCurrentIndex(index)
            self._views[index].on_activate()
            self._views[index].refresh()

    def _on_sse_event(self, event_type: str, data: dict) -> None:
        """Handle incoming SSE event."""
        if event_type == "job.update":
            if self._job_poller:
                self._job_poller._poll()
        elif event_type == "arp.update":
            current_idx = self._views_stack.currentIndex()
            if current_idx == 1:  # ARP view
                self._views[1].refresh()
            elif current_idx == 0:  # Dashboard
                self._views[0].refresh()
        elif event_type == "message":
            self._status_label.setText(data.get("message", ""))

    def _on_jobs_updated(self, jobs: list[Any]) -> None:
        running = sum(1 for j in jobs if j.get("status") in ("running", "pending"))
        self._status_label.setText(f"Jobs: {running} en cours" if running else "Prêt")
        if running:
            self._update_tray_status("scanning")
        else:
            self._update_tray_status("connected")

    def _update_tray_status(self, status: str) -> None:
        if self._tray:
            self._tray.set_status(status)

    def _quit(self) -> None:
        """Clean shutdown of app and backend."""
        if self._sse_worker:
            self._sse_worker.stop()
        if self._job_poller:
            self._job_poller.stop()
        self._backend.stop()
        QApplication.instance().quit()

    def closeEvent(self, event) -> None:
        """Override close to minimize to tray instead."""
        if self._tray and self._tray.isVisible():
            self.hide()
            self._tray.showMessage(
                "HARMATTAN",
                "L'application reste active en arrière-plan.",
                icon=self._tray.icon,
            )
            event.ignore()
        else:
            self._quit()
            event.accept()
