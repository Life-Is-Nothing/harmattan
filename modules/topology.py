"""
HARMATTAN — Hierarchical topology graph (vis-network).
Clients attach to AP/switch when present, otherwise gateway.
"""
from __future__ import annotations

from modules import network_info

ROLE_META = {
    "gateway":   {"label": "GATEWAY", "level": 0},
    "router":    {"label": "ROUTER", "level": 1},
    "ap":        {"label": "ACCESS POINT", "level": 1},
    "switch":    {"label": "SWITCH", "level": 1},
    "pc":        {"label": "PC", "level": 2},
    "apple":     {"label": "APPLE", "level": 2},
    "mobile":    {"label": "MOBILE", "level": 2},
    "raspberry": {"label": "RASPBERRY", "level": 2},
    "vm":        {"label": "VM", "level": 2},
    "iot":       {"label": "IOT", "level": 2},
    "printer":   {"label": "PRINTER", "level": 2},
    "camera":    {"label": "CAMERA", "level": 2},
    "unknown":   {"label": "UNKNOWN", "level": 2},
    "self":      {"label": "SELF", "level": 0},
}


def build_graph(arp_hosts: list, nmap_hosts: list = None, local_ip: str = None) -> dict:
    nmap_hosts = nmap_hosts or []
    nmap_by_ip = {h["ip"]: h for h in nmap_hosts}
    gateway = network_info.get_default_gateway()
    local_ip = local_ip or network_info.get_local_ip()
    subnet = network_info.get_local_subnet()

    nodes = []
    edges = []
    intermediates = 0
    seen_ids = set()

    nodes.append({
        "id": "internet",
        "label": "Internet",
        "group": "internet",
        "role": "internet",
        "level": -1,
        "shape": "diamond",
        "title": "Uplink / WAN",
    })
    seen_ids.add("internet")

    gw_id = gateway or "gateway"
    if gateway:
        gw_host = next((h for h in arp_hosts if h["ip"] == gateway), None)
        title = [f"Gateway: {gateway}"]
        if gw_host:
            title += [
                f"MAC: {gw_host.get('mac', '?')}",
                f"Vendor: {gw_host.get('vendor', '?')}",
                f"Role: {gw_host.get('role', 'gateway')}",
            ]
        nodes.append({
            "id": gw_id,
            "label": f"{gateway}\nGATEWAY",
            "group": "gateway",
            "role": "gateway",
            "level": 0,
            "shape": "hexagon",
            "title": "\n".join(title),
        })
        seen_ids.add(gw_id)
        edges.append({"from": "internet", "to": gw_id, "edge_type": "uplink", "dashes": True})
    else:
        nodes.append({
            "id": "gateway",
            "label": "Gateway\n(inconnu)",
            "group": "gateway",
            "role": "gateway",
            "level": 0,
            "shape": "hexagon",
        })
        seen_ids.add("gateway")
        edges.append({"from": "internet", "to": "gateway", "edge_type": "uplink", "dashes": True})
        gw_id = "gateway"

    if local_ip and local_ip not in seen_ids:
        nodes.append({
            "id": "self",
            "label": f"{local_ip}\nHARMATTAN",
            "group": "self",
            "role": "self",
            "level": 1,
            "shape": "dot",
            "title": f"Hôte local\n{local_ip}",
        })
        seen_ids.add("self")
        edges.append({"from": gw_id, "to": "self", "edge_type": "backbone"})

    intermediate_roles = {"router", "ap", "switch"}
    intermediate_ids = []

    for host in arp_hosts:
        role = host.get("role") or "unknown"
        if host["ip"] == gateway or host["ip"] in seen_ids:
            continue
        if role not in intermediate_roles:
            continue
        intermediates += 1
        nmap_data = nmap_by_ip.get(host["ip"], {})
        open_ports = host.get("open_ports") or [
            int(p["port"]) for p in nmap_data.get("ports", []) if p.get("state") == "open"
        ]
        label_name = host.get("hostname") or host["ip"]
        nodes.append({
            "id": host["ip"],
            "label": f"{label_name}\n{ROLE_META.get(role, {}).get('label', role).upper()}",
            "group": role,
            "role": role,
            "level": 1,
            "title": _title(host, open_ports, nmap_data),
            "ports": len(open_ports),
        })
        seen_ids.add(host["ip"])
        intermediate_ids.append(host["ip"])
        edges.append({"from": gw_id, "to": host["ip"], "edge_type": "backbone"})

    # Prefer AP > switch > router as parent for clients
    parent_for_client = gw_id
    for pref in ("ap", "switch", "router"):
        match = next((h for h in arp_hosts if h.get("role") == pref and h["ip"] != gateway), None)
        if match:
            parent_for_client = match["ip"]
            break

    for host in arp_hosts:
        role = host.get("role") or "unknown"
        if host["ip"] == gateway or host["ip"] in seen_ids:
            continue
        if role in intermediate_roles:
            continue
        if host["ip"] == local_ip:
            continue

        nmap_data = nmap_by_ip.get(host["ip"], {})
        open_ports = host.get("open_ports") or [
            int(p["port"]) for p in nmap_data.get("ports", []) if p.get("state") == "open"
        ]
        label_name = host.get("hostname") or host["ip"]
        role_label = ROLE_META.get(role, {}).get("label", role).upper()
        group = role if role != "unknown" else ("host_open_ports" if open_ports else "host")

        nodes.append({
            "id": host["ip"],
            "label": f"{label_name}\n{role_label}",
            "group": group,
            "role": role,
            "level": 2,
            "title": _title(host, open_ports, nmap_data),
            "ports": len(open_ports),
        })
        seen_ids.add(host["ip"])
        edges.append({"from": parent_for_client, "to": host["ip"], "edge_type": "client"})

    for ip, nmap_data in nmap_by_ip.items():
        if ip in seen_ids:
            continue
        open_ports = [p for p in nmap_data.get("ports", []) if p.get("state") == "open"]
        nodes.append({
            "id": ip,
            "label": ip,
            "group": "host_open_ports" if open_ports else "host",
            "role": "unknown",
            "level": 2,
            "title": f"IP: {ip}\nPorts: {len(open_ports)}",
            "ports": len(open_ports),
        })
        edges.append({"from": parent_for_client, "to": ip, "edge_type": "client"})

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "subnet": subnet,
            "gateway": gateway,
            "devices": len([n for n in nodes if n["id"] not in ("internet",)]),
            "intermediates": intermediates,
            "local_ip": local_ip,
            "parent": parent_for_client,
        },
    }


def _title(host: dict, open_ports, nmap_data: dict) -> str:
    lines = [
        f"IP: {host['ip']}",
        f"MAC: {host.get('mac', '?')}",
        f"Vendor: {host.get('vendor', 'Inconnu')}",
        f"Hostname: {host.get('hostname') or '—'}",
        f"Role: {host.get('role', 'unknown')}",
        f"OS hint: {host.get('os_hint', '—')}",
    ]
    if host.get("ttl") is not None:
        lines.append(f"TTL: {host['ttl']}")
    if open_ports:
        lines.append(f"Ports: {', '.join(str(p) for p in open_ports)}")
    if nmap_data.get("os_matches"):
        lines.append(f"OS: {nmap_data['os_matches'][0]['name']}")
    if host.get("snmp_desc"):
        lines.append(f"SNMP: {host['snmp_desc'][:80]}")
    return "\n".join(lines)
