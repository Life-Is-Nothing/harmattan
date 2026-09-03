"""Data models for HARMATTAN Desktop GUI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Host:
    mac: str = ""
    ip: str = ""
    vendor: str = ""
    hostname: str = ""
    role: str = ""
    os_hint: str = ""
    open_ports: list[int] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanJob:
    id: str = ""
    kind: str = ""
    status: str = "pending"
    progress: int = 0
    message: str = ""
    error: Optional[str] = None
    created: str = ""

    @property
    def is_running(self) -> bool:
        return self.status in ("running", "pending", "queued")

    @property
    def is_done(self) -> bool:
        return self.status in ("done", "error", "cancelled")


@dataclass
class Packet:
    no: int = 0
    time: str = ""
    src: str = ""
    dst: str = ""
    protocol: str = ""
    sport: int = 0
    dport: int = 0
    length: int = 0
    info: str = ""


@dataclass
class Notification:
    id: int = 0
    time: str = ""
    type: str = "message"
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    id: int = 0
    host_key: str = ""
    title: str = ""
    detail: str = ""
    severity: str = "medium"
    created: str = ""


@dataclass
class HealthStatus:
    ok: bool = False
    version: str = ""
    scapy: bool = False
    nmap: bool = False
    jobs_running: int = 0
    known_hosts: int = 0
    preflight: dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkInfo:
    subnet: str = ""
    gateway: str = ""
    ssid: str = ""
    interface: str = ""
    ips: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
