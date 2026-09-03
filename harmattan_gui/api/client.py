"""
HARMATTAN Desktop GUI — HTTP API Client.
Singleton wrapping QNetworkAccessManager for all backend communication.
"""
from __future__ import annotations

import json
import os
from typing import Any, Callable, Optional
from urllib.parse import urljoin

from PyQt6.QtCore import QObject, QByteArray, QUrl, pyqtSignal
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply

from harmattan_gui.api import endpoints as E

REQ_GET = 0
REQ_POST = 1
REQ_DELETE = 2


class ApiError(Exception):
    """API request error."""

    def __init__(self, status: int, message: str = ""):
        self.status = status
        self.message = message
        super().__init__(f"API error {status}: {message}")


class ApiClient(QObject):
    """Singleton HTTP client for the HARMATTAN backend."""

    health_changed = pyqtSignal(bool)
    auth_failed = pyqtSignal()
    rate_limited = pyqtSignal(int)  # retry-after seconds
    network_error = pyqtSignal(str)

    _instance: Optional["ApiClient"] = None

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._manager = QNetworkAccessManager(self)
        self._base_url = os.environ.get("HARMATTAN_URL", E.BASE_URL)
        self._token: str = ""
        self._load_token()

    @classmethod
    def instance(cls, parent: Optional[QObject] = None) -> "ApiClient":
        if cls._instance is None:
            cls._instance = cls(parent)
        return cls._instance

    def _load_token(self) -> None:
        """Load API token from env, file, or keyring."""
        token = os.environ.get("HARMATTAN_TOKEN", "").strip()
        if not token:
            token_file = os.path.expanduser("~/.config/harmattan/api_token")
            if os.path.isfile(token_file):
                with open(token_file) as f:
                    token = f.read().strip()
        if not token:
            # Try keyring
            try:
                import keyring
                token = keyring.get_password("harmattan", "api_token") or ""
            except Exception:
                pass
        self._token = token

    def set_token(self, token: str) -> None:
        self._token = token
        # Save to keyring
        try:
            import keyring
            keyring.set_password("harmattan", "api_token", token)
        except Exception:
            pass

    def _build_request(self, path: str, method: int = REQ_GET) -> QNetworkRequest:
        url = urljoin(self._base_url, path)
        req = QNetworkRequest(QUrl(url))
        req.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")
        if self._token:
            req.setRawHeader(b"X-Harmattan-Token", self._token.encode())
        req.setTransferTimeout(30000)
        return req

    def _handle_response(self, reply: QNetworkReply, callback: Optional[Callable[[Any], None]] = None,
                         errback: Optional[Callable[[ApiError], None]] = None) -> None:
        reply.deleteLater()
        status = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
        if status is None:
            status = 0
        data = reply.readAll().data()

        if reply.error() == QNetworkReply.NetworkError.ConnectionRefusedError:
            self.network_error.emit("Connection refused — is the backend running?")
            self.health_changed.emit(False)
            if errback:
                errback(ApiError(0, "Connection refused"))
            return

        if status == 401:
            self.auth_failed.emit()
            if errback:
                errback(ApiError(401, "Unauthorized"))
            return

        if status == 429:
            retry_after = 60
            try:
                retry_header = reply.rawHeader(b"Retry-After")
                if retry_header:
                    retry_after = int(retry_header.decode())
            except (ValueError, TypeError):
                pass
            self.rate_limited.emit(retry_after)
            if errback:
                errback(ApiError(429, f"Rate limited, retry after {retry_after}s"))
            return

        if status >= 400:
            msg = ""
            try:
                body = json.loads(data) if data else {}
                msg = body.get("message", body.get("error", str(status)))
            except (json.JSONDecodeError, TypeError):
                msg = data.decode("utf-8", errors="replace")[:200]
            if errback:
                errback(ApiError(status, msg))
            return

        self.health_changed.emit(True)

        if callback:
            try:
                if data:
                    result = json.loads(data)
                else:
                    result = {}
                callback(result)
            except json.JSONDecodeError as e:
                if errback:
                    errback(ApiError(0, f"JSON decode error: {e}"))

    def get(self, path: str, callback: Optional[Callable[[Any], None]] = None,
            errback: Optional[Callable[[ApiError], None]] = None) -> QNetworkReply:
        req = self._build_request(path, REQ_GET)
        reply = self._manager.get(req)
        reply.finished.connect(lambda: self._handle_response(reply, callback, errback))
        return reply

    def post(self, path: str, data: Optional[dict] = None,
             callback: Optional[Callable[[Any], None]] = None,
             errback: Optional[Callable[[ApiError], None]] = None) -> QNetworkReply:
        req = self._build_request(path, REQ_POST)
        body = QByteArray(json.dumps(data or {}).encode())
        reply = self._manager.post(req, body)
        reply.finished.connect(lambda: self._handle_response(reply, callback, errback))
        return reply

    def delete(self, path: str, callback: Optional[Callable[[Any], None]] = None,
               errback: Optional[Callable[[ApiError], None]] = None) -> QNetworkReply:
        req = self._build_request(path, REQ_DELETE)
        reply = self._manager.delete(req)
        reply.finished.connect(lambda: self._handle_response(reply, callback, errback))
        return reply

    # ---- Convenience methods for specific endpoints ----

    def check_health(self, callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.get(E.HEALTH, callback=callback)

    def get_network_info(self, callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.get(E.NETWORK_INFO, callback=callback)

    def get_preflight(self, callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.get(E.PREFLIGHT, callback=callback)

    def list_jobs(self, callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.get(E.JOBS, callback=callback)

    def cancel_job(self, job_id: str, callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.post(E.JOBS_CANCEL.format(job_id=job_id), callback=callback)

    def run_arp_scan(self, subnet: str, iface: str = "", enrich: bool = True,
                     async_mode: bool = True,
                     callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        data = {"subnet": subnet, "enrich": enrich, "async": async_mode}
        if iface:
            data["iface"] = iface
        return self.post(E.ARP_SCAN, data, callback=callback)

    def run_nmap_scan(self, target: str, profile: str = "quick",
                      custom_args: str = "",
                      callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.post(E.NMAP_SCAN, {
            "target": target,
            "profile": profile,
            "custom_args": custom_args,
        }, callback=callback)

    def get_attack_surface(self, callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.get(E.ATTACK_SURFACE, callback=callback)

    def get_topology(self, callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.get(E.TOPOLOGY, callback=callback)

    def get_host_detail(self, ip: str, callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.get(E.HOST_DETAIL.format(ip=ip), callback=callback)

    def get_traffic_packets(self, offset: int = 0, limit: int = 100,
                            callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.get(f"{E.TRAFFIC_PACKETS}?offset={offset}&limit={limit}", callback=callback)

    def get_notifications(self, callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.get(E.NOTIFICATIONS, callback=callback)

    def get_ai_analysis(self, callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.get(E.AI_ANALYZE, callback=callback)

    def get_mitre(self, callback: Optional[Callable[[Any], None]] = None) -> QNetworkReply:
        return self.get(E.MITRE, callback=callback)
