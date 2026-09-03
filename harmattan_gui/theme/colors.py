"""HARMATTAN Desktop GUI — Color constants."""
from __future__ import annotations

# Severity colors
SEVERITY_COLORS = {
    "critique": "#DC2626",
    "haute": "#EA580C",
    "moyenne": "#EAB308",
    "faible": "#22C55E",
    "info": "#3B82F6",
    "open": "#6B7280",
    "filtered": "#8B5CF6",
    "closed": "#22C55E",
}

# Protocol colors for packet list (Wireshark-style)
PROTOCOL_COLORS = {
    "TCP": "#3B82F6",
    "UDP": "#8B5CF6",
    "ARP": "#EC4899",
    "ICMP": "#22C55E",
    "DNS": "#F59E0B",
    "HTTP": "#0D9488",
    "HTTPS": "#0D9488",
    "DHCP": "#6366F1",
    "MDNS": "#F97316",
    "LLMNR": "#EF4444",
    "STP": "#14B8A6",
    "SSH": "#22C55E",
    "TLS": "#3B82F6",
}

# Host role colors
ROLE_COLORS = {
    "router": "#EF4444",
    "switch": "#F97316",
    "firewall": "#DC2626",
    "server": "#3B82F6",
    "workstation": "#22C55E",
    "printer": "#8B5CF6",
    "phone": "#EC4899",
    "camera": "#14B8A6",
    "iot": "#84CC16",
    "nas": "#0D9488",
    "vm": "#6366F1",
    "container": "#0EA5E9",
    "unknown": "#6B7280",
}

# Dashboard stat colors
STAT_COLORS = {
    "total": "#3B82F6",
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#EAB308",
    "low": "#22C55E",
}
