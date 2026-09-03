"""Tests for HARMATTAN GUI models and API endpoints definitions."""
from __future__ import annotations

from harmattan_gui.api.models import (
    Host, ScanJob, Packet, Notification, Finding, HealthStatus, NetworkInfo,
)
from harmattan_gui.api.endpoints import (
    HEALTH, PREFLIGHT, ARP_SCAN, NMAP_SCAN, TOPOLOGY, TRAFFIC_PACKETS,
    NOTIFICATIONS, AI_ANALYZE, PLUGINS, EXPORT_CSV,
)


class TestGuiModels:
    def test_host_defaults(self):
        h = Host()
        assert h.mac == ""
        assert h.ip == ""
        assert h.open_ports == []

    def test_host_with_values(self):
        h = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", role="router")
        assert h.ip == "192.168.1.1"
        assert h.mac == "aa:bb:cc:dd:ee:ff"
        assert h.role == "router"

    def test_scan_job_status(self):
        running = ScanJob(status="running")
        assert running.is_running is True
        assert running.is_done is False
        done = ScanJob(status="done")
        assert done.is_running is False
        assert done.is_done is True

    def test_packet_defaults(self):
        p = Packet()
        assert p.no == 0
        assert p.protocol == ""

    def test_notification_defaults(self):
        n = Notification()
        assert n.type == "message"

    def test_finding_defaults(self):
        f = Finding()
        assert f.severity == "medium"

    def test_health_status_defaults(self):
        h = HealthStatus()
        assert h.ok is False

    def test_network_info_defaults(self):
        n = NetworkInfo()
        assert n.subnet == ""
        assert n.ips == []


class TestApiEndpoints:
    def test_base_endpoints_exist(self):
        assert HEALTH == "/api/v1/health"
        assert PREFLIGHT == "/api/v1/preflight"
        assert ARP_SCAN == "/api/v1/arp-scan"
        assert NMAP_SCAN == "/api/v1/nmap-scan"

    def test_feature_endpoints_exist(self):
        assert TOPOLOGY == "/api/v1/topology"
        assert TRAFFIC_PACKETS == "/api/v1/traffic/packets"
        assert NOTIFICATIONS == "/api/v1/notifications"
        assert AI_ANALYZE == "/api/v1/ai-analyze"

    def test_new_endpoints_exist(self):
        assert PLUGINS == "/api/v1/plugins"
        assert EXPORT_CSV == "/api/v1/export/csv"
