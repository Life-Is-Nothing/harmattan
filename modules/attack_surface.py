"""
HARMATTAN — Attack surface: exposed services, risk scoring, recommendations.
"""
from __future__ import annotations

from modules.fingerprinting import SENSITIVE_PORTS

RECOMMENDATIONS = {
    21: "Désactiver FTP en clair ou forcer FTPS/SFTP.",
    22: "Restreindre SSH (clés, fail2ban, pas de root login).",
    23: "Telnet est non chiffré — désactiver immédiatement.",
    135: "RPC exposé — filtrer hors LAN de confiance.",
    139: "NetBIOS — désactiver si inutile.",
    445: "SMB exposé — patcher, SMBv1 off, segments isolés.",
    1433: "MSSQL — ne pas exposer hors admin, MFA/VPN.",
    3306: "MySQL — bind localhost ou firewall strict.",
    3389: "RDP exposé — NLA + VPN, jamais Internet direct.",
    5432: "PostgreSQL — restreindre aux admins.",
    5900: "VNC souvent faible — tunnel SSH ou désactiver.",
    8080: "HTTP alt — vérifier auth et HTTPS.",
}


def _risk_for_port(port: int, service: str = "") -> str:
    critical = {23, 445, 3389, 1433, 5900}
    high = {21, 22, 135, 139, 3306, 5432, 554, 161}
    medium = {80, 8080, 8443, 443, 25, 110, 143}
    if port in critical:
        return "critique"
    if port in high:
        return "haute"
    if port in medium:
        return "moyenne"
    return "faible"


def _risk_score(risk_counts: dict) -> int:
    """0–100 network exposure score (higher = worse)."""
    score = (
        risk_counts.get("critique", 0) * 25
        + risk_counts.get("haute", 0) * 12
        + risk_counts.get("moyenne", 0) * 5
        + risk_counts.get("faible", 0) * 1
    )
    return min(100, score)


def build_attack_surface(arp_hosts: list | None = None, nmap_hosts: list | None = None) -> dict:
    arp_hosts = arp_hosts or []
    nmap_hosts = nmap_hosts or []
    nmap_by_ip = {h["ip"]: h for h in nmap_hosts}

    hosts_out = []
    total_exposures = 0
    risk_counts = {"critique": 0, "haute": 0, "moyenne": 0, "faible": 0}
    recommendations: list[str] = []
    rec_seen = set()

    all_ips = {h["ip"] for h in arp_hosts} | set(nmap_by_ip.keys())

    def _sort_ip(x: str):
        parts = x.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return tuple(int(p) for p in parts)
        return (999, 999, 999, 999)

    for ip in sorted(all_ips, key=_sort_ip):
        arp = next((h for h in arp_hosts if h["ip"] == ip), {})
        nmap = nmap_by_ip.get(ip, {})

        exposures = []
        seen_ports = set()

        for p in nmap.get("ports", []):
            if p.get("state") != "open":
                continue
            port = int(p["port"])
            seen_ports.add(port)
            risk = _risk_for_port(port, p.get("service", ""))
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            total_exposures += 1
            exposures.append({
                "port": port,
                "protocol": p.get("protocol", "tcp"),
                "service": p.get("service") or SENSITIVE_PORTS.get(port, ""),
                "product": p.get("product", ""),
                "version": p.get("version", ""),
                "risk": risk,
                "source": "nmap",
                "scripts": p.get("scripts", []),
                "recommendation": RECOMMENDATIONS.get(port, ""),
            })
            if port in RECOMMENDATIONS and port not in rec_seen:
                rec_seen.add(port)
                recommendations.append(f"{ip}:{port} — {RECOMMENDATIONS[port]}")

        for port in arp.get("open_ports", []):
            if port in seen_ports:
                continue
            risk = _risk_for_port(port)
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            total_exposures += 1
            exposures.append({
                "port": port,
                "protocol": "tcp",
                "service": SENSITIVE_PORTS.get(port, ""),
                "product": "",
                "version": "",
                "risk": risk,
                "source": "probe",
                "scripts": [],
                "recommendation": RECOMMENDATIONS.get(port, ""),
            })
            if port in RECOMMENDATIONS and port not in rec_seen:
                rec_seen.add(port)
                recommendations.append(f"{ip}:{port} — {RECOMMENDATIONS[port]}")

        if not exposures and not arp and not nmap:
            continue

        exposures_sorted = sorted(
            exposures,
            key=lambda e: (
                {"critique": 0, "haute": 1, "moyenne": 2, "faible": 3}.get(e["risk"], 9),
                e["port"],
            ),
        )
        hostnames = nmap.get("hostnames") or []
        hosts_out.append({
            "ip": ip,
            "hostname": arp.get("hostname") or (hostnames[0] if hostnames else ""),
            "mac": arp.get("mac") or nmap.get("mac"),
            "vendor": arp.get("vendor", ""),
            "role": arp.get("role", "unknown"),
            "os_hint": arp.get("os_hint") or (
                nmap["os_matches"][0]["name"] if nmap.get("os_matches") else ""
            ),
            "exposures": exposures_sorted,
            "exposure_count": len(exposures_sorted),
            "max_risk": exposures_sorted[0]["risk"] if exposures_sorted else "none",
        })

    hosts_out.sort(key=lambda h: (
        {"critique": 0, "haute": 1, "moyenne": 2, "faible": 3, "none": 9}.get(h["max_risk"], 9),
        -h["exposure_count"],
    ))

    score = _risk_score(risk_counts)
    if score >= 70:
        grade = "F"
    elif score >= 50:
        grade = "D"
    elif score >= 35:
        grade = "C"
    elif score >= 20:
        grade = "B"
    else:
        grade = "A"

    return {
        "hosts": hosts_out,
        "total_hosts": len(hosts_out),
        "total_exposures": total_exposures,
        "risk_counts": risk_counts,
        "risk_score": score,
        "grade": grade,
        "recommendations": recommendations[:25],
    }
