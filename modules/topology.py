"""
HARMATTAN — Topology graph (vis-network) with professional device icons.
"""
from __future__ import annotations

from modules import network_info

# Rôle → icône SVG (static/img/devices/<icon>.svg) + taille
ROLE_META = {
    "internet":  {"label": "INTERNET", "level": -1, "icon": "internet", "size": 42},
    "gateway":   {"label": "GATEWAY", "level": 0, "icon": "gateway", "size": 48},
    "router":    {"label": "ROUTER", "level": 1, "icon": "router", "size": 40},
    "ap":        {"label": "WI-FI AP", "level": 1, "icon": "ap", "size": 40},
    "switch":    {"label": "SWITCH", "level": 1, "icon": "switch", "size": 38},
    "pc":        {"label": "PC", "level": 2, "icon": "pc", "size": 34},
    "server":    {"label": "SERVER", "level": 2, "icon": "server", "size": 36},
    "apple":     {"label": "APPLE", "level": 2, "icon": "apple", "size": 34},
    "android":   {"label": "ANDROID", "level": 2, "icon": "android", "size": 36},
    "mobile":    {"label": "MOBILE", "level": 2, "icon": "mobile", "size": 32},
    "raspberry": {"label": "PI", "level": 2, "icon": "raspberry", "size": 32},
    "vm":        {"label": "VM", "level": 2, "icon": "vm", "size": 30},
    "iot":       {"label": "IOT", "level": 2, "icon": "iot", "size": 30},
    "printer":   {"label": "PRINT", "level": 2, "icon": "printer", "size": 32},
    "camera":    {"label": "CAM", "level": 2, "icon": "camera", "size": 32},
    "tv":        {"label": "TV / STB", "level": 2, "icon": "tv", "size": 32},
    "unknown":   {"label": "HOST", "level": 2, "icon": "unknown", "size": 28},
    "self":      {"label": "HARMATTAN", "level": 1, "icon": "self", "size": 42},
    "host":      {"label": "HOST", "level": 2, "icon": "host", "size": 28},
    "host_open_ports": {"label": "HOST", "level": 2, "icon": "host", "size": 32},
}


def _meta(role: str) -> dict:
    return ROLE_META.get(role) or ROLE_META["unknown"]


def _icon_url(role: str) -> str:
    m = _meta(role)
    return f"/static/img/devices/{m['icon']}.svg"


def _node_label(name: str, role: str, subtitle: str = "") -> str:
    m = _meta(role)
    role_l = m.get("label", role).upper()
    head = (name or "")[:28]
    if subtitle:
        return f"{head}\n{role_l}\n{subtitle[:24]}"
    return f"{head}\n{role_l}"


def build_graph(arp_hosts: list, nmap_hosts: list = None, local_ip: str = None) -> dict:
    nmap_hosts = nmap_hosts or []
    nmap_by_ip = {h["ip"]: h for h in nmap_hosts if h.get("ip")}
    gateway = network_info.get_default_gateway()
    local_ip = local_ip or network_info.get_local_ip()
    subnet = network_info.get_local_subnet()

    nodes = []
    edges = []
    intermediates = 0
    seen_ids = set()
    role_counts: dict[str, int] = {}
    # Subnet bounding boxes (CIDR overlays for UI / Gephi meta)
    subnets_set: set[str] = set()
    if subnet:
        subnets_set.add(subnet)

    def bump(role: str):
        role_counts[role] = role_counts.get(role, 0) + 1

    # --- Internet ---
    nodes.append(_mk_node(
        nid="internet",
        role="internet",
        label=_node_label("Internet", "internet", "WAN"),
        title="Uplink / sortie Internet",
        level=-1,
    ))
    seen_ids.add("internet")
    bump("internet")

    # --- Gateway ---
    gw_id = gateway or "gateway"
    if gateway:
        gw_host = next((h for h in arp_hosts if h.get("ip") == gateway), None)
        title_parts = [f"Gateway: {gateway}"]
        if gw_host:
            title_parts += [
                f"MAC: {gw_host.get('mac', '?')}",
                f"Vendor: {gw_host.get('vendor', '?')}",
                f"Role: {gw_host.get('role', 'gateway')}",
            ]
        nodes.append(_mk_node(
            nid=gw_id,
            role="gateway",
            label=_node_label(gateway, "gateway", (gw_host or {}).get("vendor") or ""),
            title="\n".join(title_parts),
            level=0,
            extra={"ip": gateway, "mac": (gw_host or {}).get("mac"), "vendor": (gw_host or {}).get("vendor")},
        ))
        seen_ids.add(gw_id)
        edges.append(_mk_edge("internet", gw_id, "uplink"))
        bump("gateway")
    else:
        nodes.append(_mk_node(
            nid="gateway",
            role="gateway",
            label=_node_label("Gateway", "gateway", "inconnu"),
            title="Passerelle non détectée",
            level=0,
        ))
        seen_ids.add("gateway")
        edges.append(_mk_edge("internet", "gateway", "uplink"))
        gw_id = "gateway"
        bump("gateway")

    # --- Self ---
    if local_ip and local_ip not in seen_ids:
        nodes.append(_mk_node(
            nid="self",
            role="self",
            label=_node_label(local_ip, "self", "ce poste"),
            title=f"Hôte local HARMATTAN\n{local_ip}",
            level=1,
            extra={"ip": local_ip},
        ))
        seen_ids.add("self")
        edges.append(_mk_edge(gw_id, "self", "backbone"))
        bump("self")

    intermediate_roles = {"router", "ap", "switch"}
    intermediate_ids = []

    for host in arp_hosts:
        role = host.get("role") or "unknown"
        ip = host.get("ip")
        if not ip or ip == gateway or ip in seen_ids:
            continue
        if role not in intermediate_roles:
            continue
        intermediates += 1
        nmap_data = nmap_by_ip.get(ip, {})
        open_ports = _ports(host, nmap_data)
        name = host.get("custom_label") or host.get("hostname") or ip
        sub = host.get("vendor") or (f"{len(open_ports)} ports" if open_ports else "")
        if host.get("default_cred_flags"):
            sub = "⚠ DEFAULT-CRED? " + (sub or "")
        nodes.append(_mk_node(
            nid=ip,
            role=role,
            label=_node_label(name, role, sub[:28] if sub else ""),
            title=_title(host, open_ports, nmap_data),
            level=1,
            ports=len(open_ports),
            extra={
                "ip": ip,
                "mac": host.get("mac"),
                "vendor": host.get("vendor"),
                "hostname": host.get("hostname"),
                "custom_label": host.get("custom_label"),
                "device_type": role,
                "parent": host.get("parent") or gw_id,
            },
        ))
        seen_ids.add(ip)
        intermediate_ids.append(ip)
        edges.append(_mk_edge(gw_id, ip, "backbone"))
        bump(role)

    parent_for_client = gw_id
    for pref in ("ap", "switch", "router"):
        match = next((h for h in arp_hosts if h.get("role") == pref and h.get("ip") != gateway), None)
        if match:
            parent_for_client = match["ip"]
            break

    for host in arp_hosts:
        role = host.get("role") or "unknown"
        ip = host.get("ip")
        if not ip or ip == gateway or ip in seen_ids:
            continue
        if role in intermediate_roles:
            continue
        if ip == local_ip:
            continue

        nmap_data = nmap_by_ip.get(ip, {})
        open_ports = _ports(host, nmap_data)
        name = host.get("custom_label") or host.get("hostname") or ip
        if role == "unknown":
            role = "host_open_ports" if open_ports else "host"
        vendor = (host.get("vendor") or "")[:22]
        port_hint = f":{open_ports[0]}" if open_ports else ""
        sub = vendor or (f"{len(open_ports)} ports" if open_ports else "")
        if host.get("default_cred_flags"):
            sub = "⚠ CRED " + (sub or "")
            size_boost = min(10, len(open_ports) * 2 + 4)
        else:
            size_boost = min(8, len(open_ports) * 2)

        # parent: explicit (range_map) > AP/switch > gateway
        parent = host.get("parent") or parent_for_client
        if parent and parent not in seen_ids and parent != gw_id:
            # create stub intermediate parent (remote hop)
            nodes.append(_mk_node(
                nid=parent,
                role="router",
                label=_node_label(parent, "router", "hop"),
                title=f"Parent hop / router\n{parent}",
                level=1,
                extra={"ip": parent, "device_type": "router", "virtual_hop": True},
            ))
            seen_ids.add(parent)
            edges.append(_mk_edge(gw_id, parent, "backbone"))
            intermediate_ids.append(parent)
            intermediates += 1
            bump("router")
        if not parent or parent not in seen_ids:
            parent = parent_for_client

        nodes.append(_mk_node(
            nid=ip,
            role=role,
            label=_node_label(f"{name}{port_hint}", role, sub),
            title=_title(host, open_ports, nmap_data),
            level=2,
            ports=len(open_ports),
            size_boost=size_boost,
            extra={
                "ip": ip,
                "mac": host.get("mac"),
                "vendor": host.get("vendor"),
                "hostname": host.get("hostname"),
                "custom_label": host.get("custom_label"),
                "device_type": role,
                "parent": parent,
                "default_cred": bool(host.get("default_cred_flags")),
            },
        ))
        seen_ids.add(ip)
        edges.append(_mk_edge(parent, ip, "client"))
        bump(role)

    for ip, nmap_data in nmap_by_ip.items():
        if ip in seen_ids:
            continue
        open_ports = [
            int(p["port"]) for p in nmap_data.get("ports", [])
            if p.get("state") == "open" and str(p.get("port", "")).isdigit()
        ]
        role = "host_open_ports" if open_ports else "host"
        nodes.append(_mk_node(
            nid=ip,
            role=role,
            label=_node_label(ip, role, f"{len(open_ports)} ports" if open_ports else ""),
            title=f"IP: {ip}\nPorts: {', '.join(str(p) for p in open_ports) or '—'}",
            level=2,
            ports=len(open_ports),
            extra={"ip": ip, "device_type": role},
        ))
        edges.append(_mk_edge(parent_for_client, ip, "client"))
        bump(role)

    host_nodes = [n for n in nodes if n["id"] not in ("internet",)]
    # Collect subnets from host IPs for bounding boxes (L0p4Map-style)
    try:
        import ipaddress

        for h in arp_hosts:
            ip = h.get("ip")
            if not ip:
                continue
            try:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                subnets_set.add(str(net))
            except Exception:
                pass
    except Exception:
        pass

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "subnet": subnet,
            "gateway": gateway,
            "devices": len(host_nodes),
            "intermediates": intermediates,
            "local_ip": local_ip,
            "parent": parent_for_client,
            "empty": len(arp_hosts) == 0 and len(nmap_hosts) == 0,
            "role_counts": role_counts,
            "icons": {r: _icon_url(r) for r in ROLE_META},
            "subnet_boxes": sorted(subnets_set),
            "edge_types": ["uplink", "backbone", "client"],
        },
    }


def _ports(host: dict, nmap_data: dict) -> list:
    if host.get("open_ports"):
        return list(host["open_ports"])
    out = []
    for p in nmap_data.get("ports", []) or []:
        if p.get("state") == "open":
            try:
                out.append(int(p["port"]))
            except (TypeError, ValueError, KeyError):
                pass
    return out


def _mk_node(
    nid: str,
    role: str,
    label: str,
    title: str,
    level: int,
    ports: int = 0,
    size_boost: int = 0,
    extra: dict | None = None,
) -> dict:
    m = _meta(role)
    size = int(m.get("size", 28)) + size_boost
    icon = _icon_url(role)
    node = {
        "id": nid,
        "label": label,
        "group": role,
        "role": role,
        "level": level,
        # vis-network image node
        "shape": "image",
        "image": icon,
        "brokenImage": "/static/img/devices/unknown.svg",
        "size": size,
        "title": title,
        "ports": ports,
        "device_type": role,
        "icon": icon,
        "borderWidth": 0,
        "font": {
            "color": "#e8eef9",
            "size": 12 if level <= 0 else 11,
            "face": "IBM Plex Mono, ui-monospace, monospace",
            "multi": True,
            "align": "center",
            "strokeWidth": 3,
            "strokeColor": "#0a0d12",
            "vadjust": 2,
        },
    }
    if extra:
        node.update(extra)
    return node


def _mk_edge(frm: str, to: str, edge_type: str) -> dict:
    styles = {
        "uplink": {
            "dashes": [6, 4],
            "width": 2,
            "color": {"color": "#5a6578", "highlight": "#94a3b8"},
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.6}},
            "smooth": {"type": "curvedCW", "roundness": 0.18},
        },
        "backbone": {
            "dashes": False,
            "width": 3,
            "color": {"color": "#2fd9d0", "highlight": "#7aefe8"},
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.55}},
            "smooth": {"type": "cubicBezier", "forceDirection": "vertical", "roundness": 0.4},
        },
        "client": {
            "dashes": False,
            "width": 1.4,
            "color": {"color": "#3a4558", "highlight": "#f77f00"},
            "arrows": {"to": {"enabled": False}},
            "smooth": {"type": "continuous", "roundness": 0.45},
        },
    }
    st = styles.get(edge_type, styles["client"])
    return {"from": frm, "to": to, "edge_type": edge_type, **st}


def _title(host: dict, open_ports, nmap_data: dict) -> str:
    role = host.get("role", "unknown")
    lines = [
        f"📱 Type: {_meta(role).get('label', role)}",
        f"IP: {host.get('ip')}",
        f"MAC: {host.get('mac', '?')}",
        f"Vendor: {host.get('vendor', 'Inconnu')}",
        f"Hostname: {host.get('hostname') or '—'}",
        f"OS hint: {host.get('os_hint', '—')}",
    ]
    if host.get("ttl") is not None:
        lines.append(f"TTL: {host['ttl']}")
    if open_ports:
        lines.append(f"Ports: {', '.join(str(p) for p in open_ports[:20])}")
    if nmap_data.get("os_matches"):
        try:
            lines.append(f"OS: {nmap_data['os_matches'][0]['name']}")
        except (IndexError, KeyError, TypeError):
            pass
    if host.get("snmp_desc"):
        lines.append(f"SNMP: {str(host['snmp_desc'])[:80]}")
    return "\n".join(lines)
