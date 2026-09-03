"""
HARMATTAN Network — AI Analyst v4
Executive + tactical + attack-path intelligence over ARP/nmap/attack surface.
Optional bridge to harmattan-ai (LLM) and local scoring.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Optional

# Port → (label, risk_fr, mitre)
SERVICE_INTEL = {
    21: ("FTP", "critique", "T1021"),
    22: ("SSH", "haute", "T1021.004"),
    23: ("Telnet", "critique", "T1021"),
    25: ("SMTP", "moyenne", "T1071"),
    53: ("DNS", "moyenne", "T1071.004"),
    80: ("HTTP", "moyenne", "T1190"),
    110: ("POP3", "moyenne", "T1114"),
    135: ("RPC", "haute", "T1021"),
    139: ("NetBIOS", "haute", "T1021.002"),
    143: ("IMAP", "moyenne", "T1114"),
    161: ("SNMP", "haute", "T1040"),
    389: ("LDAP", "haute", "T1087"),
    443: ("HTTPS", "faible", "T1071"),
    445: ("SMB", "critique", "T1021.002"),
    554: ("RTSP", "haute", "T1120"),
    631: ("IPP", "faible", "T1120"),
    993: ("IMAPS", "faible", "T1114"),
    1433: ("MSSQL", "critique", "T1210"),
    1521: ("Oracle", "critique", "T1210"),
    1883: ("MQTT", "haute", "T1040"),
    2049: ("NFS", "haute", "T1021"),
    3306: ("MySQL", "critique", "T1210"),
    3389: ("RDP", "critique", "T1021.001"),
    5432: ("PostgreSQL", "critique", "T1210"),
    5900: ("VNC", "critique", "T1021"),
    5985: ("WinRM", "haute", "T1021.006"),
    5986: ("WinRM-S", "haute", "T1021.006"),
    6379: ("Redis", "critique", "T1210"),
    6443: ("K8s-API", "haute", "T1610"),
    8000: ("HTTP-alt", "moyenne", "T1190"),
    8080: ("HTTP-alt", "moyenne", "T1190"),
    8443: ("HTTPS-alt", "moyenne", "T1190"),
    9200: ("Elasticsearch", "critique", "T1210"),
    27017: ("MongoDB", "critique", "T1210"),
    2375: ("Docker-API", "critique", "T1610"),
    4840: ("OPC-UA", "haute", "T0801"),
    502: ("Modbus", "haute", "T0801"),
    102: ("S7comm", "haute", "T0801"),
}

RISK_ORDER = {"critique": 4, "haute": 3, "moyenne": 2, "faible": 1, "unknown": 0}


def analyze_network(
    attack_surface: dict | None = None,
    intel_data: dict | None = None,
    *,
    arp_hosts: list | None = None,
    nmap_hosts: list | None = None,
    network_snap: dict | None = None,
    use_external_ai: bool = True,
) -> dict:
    """Full network AI analysis. Builds attack surface if missing pieces provided."""
    attack_surface = dict(attack_surface or {})
    intel_data = intel_data or {}
    arp_hosts = arp_hosts or []
    nmap_hosts = nmap_hosts or []
    network_snap = network_snap or {}

    # If attack surface empty but we have scan data, build lightly
    if not attack_surface.get("hosts") and (arp_hosts or nmap_hosts):
        try:
            from modules.attack_surface import build_attack_surface

            attack_surface = build_attack_surface(arp_hosts, nmap_hosts)
        except Exception:
            attack_surface = _fallback_surface(arp_hosts, nmap_hosts)

    hosts = [h for h in (attack_surface.get("hosts") or []) if isinstance(h, dict)]
    grade = attack_surface.get("grade") or _grade_from_score(attack_surface.get("risk_score"))
    total_hosts = int(attack_surface.get("total_hosts") or len(hosts) or len(arp_hosts) or 0)
    risk_score = float(attack_surface.get("risk_score") or 0)
    risk_counts = dict(attack_surface.get("risk_counts") or {})
    for k in ("critique", "haute", "moyenne", "faible"):
        risk_counts.setdefault(k, 0)

    # Enrich from nmap/arp if exposures missing
    hosts = _merge_host_context(hosts, arp_hosts, nmap_hosts)

    port_stats = _port_statistics(hosts)
    role_stats = Counter((h.get("role") or h.get("type") or "unknown") for h in hosts)
    vendor_stats = Counter(
        (h.get("vendor") or h.get("oui") or "unknown")[:40] for h in hosts
    )
    hot_hosts = _hot_hosts(hosts)
    insecure = _insecure_findings(hosts)
    mitre = _mitre_map(insecure, risk_counts)
    severity = _severity(grade, risk_score, risk_counts, insecure)
    summary = _summary(severity, grade, risk_score, total_hosts, risk_counts, network_snap)
    priority_actions = _priority_actions(
        severity, risk_counts, total_hosts, insecure, hot_hosts, intel_data, port_stats
    )
    quick_wins = _quick_wins(insecure)
    posture = _posture_checklist(hosts, network_snap, risk_counts)

    attack_paths = _attack_paths(hosts, network_snap)
    blast = _blast_radius(hosts, insecure, hot_hosts)
    segmentation = _segmentation_plan(hosts, role_stats, risk_counts)
    sla = _remediation_sla(risk_counts, severity)
    confidence = _confidence(hosts, arp_hosts, nmap_hosts, attack_surface)
    narratives = _host_narratives(hot_hosts[:6])
    matrix = _risk_matrix(hosts)
    executive = _executive_brief(
        severity, grade, risk_score, total_hosts, risk_counts, network_snap, hot_hosts, insecure
    )

    result: dict[str, Any] = {
        "ok": True,
        "engine": "network-ai-v4",
        "summary": summary,
        "executive_brief": executive,
        "severity": severity,
        "grade": grade,
        "risk_score": risk_score,
        "confidence": confidence,
        "total_hosts": total_hosts,
        "risk_counts": risk_counts,
        "priority_actions": priority_actions,
        "quick_wins": quick_wins,
        "hot_hosts": hot_hosts,
        "host_narratives": narratives,
        "insecure_services": insecure[:40],
        "port_stats": port_stats[:15],
        "roles": dict(role_stats.most_common(12)),
        "vendors": dict(vendor_stats.most_common(10)),
        "mitre": mitre,
        "posture": posture,
        "attack_paths": attack_paths,
        "blast_radius": blast,
        "segmentation": segmentation,
        "remediation_sla": sla,
        "risk_matrix": matrix,
        "network": {
            "local_ip": network_snap.get("local_ip"),
            "gateway": network_snap.get("gateway"),
            "subnet": network_snap.get("subnet"),
            "ssid": network_snap.get("ssid"),
            "iface": network_snap.get("capture_iface") or network_snap.get("iface"),
        },
        "intel": {
            "anomaly_count": intel_data.get("anomaly_count"),
            "method": intel_data.get("method"),
            "scored_hosts": len(intel_data.get("hosts") or intel_data.get("scores") or [])
            if isinstance(intel_data, dict)
            else 0,
        },
        "analysis_date": datetime.now().isoformat(timespec="seconds"),
        "advice": (
            "1) Corrige les ports critiques (Telnet/RDP/SMB/DB). "
            "2) Isole IoT/caméras sur VLAN dédié. "
            "3) Lance Policy (:8085) pour conformité. "
            "4) Exporte un rapport client (HTML/PDF). "
            "5) Active Monitor ARP + Watch pour détection continue."
        ),
    }

    # Optional external AI assist summary (harmattan-ai)
    if use_external_ai:
        ext = _call_external_ai(result)
        if ext:
            result["external_ai"] = ext
            # Merge LLM findings into narrative when available
            if ext.get("ok") and ext.get("findings"):
                result["llm_highlights"] = ext.get("findings")

    return result


def analyze_host(ip: str, host: dict | None = None, attack: dict | None = None) -> dict:
    """Per-host AI briefing."""
    host = dict(host or {})
    if not host and attack:
        host = next((h for h in (attack.get("hosts") or []) if h.get("ip") == ip), {}) or {}
    exposures = host.get("exposures") or []
    ports = []
    for e in exposures:
        if isinstance(e, dict) and e.get("port"):
            ports.append(int(e["port"]))
    for p in host.get("open_ports") or host.get("ports") or []:
        if isinstance(p, dict):
            try:
                ports.append(int(p.get("port")))
            except Exception:
                pass
        else:
            try:
                ports.append(int(p))
            except Exception:
                pass
    ports = sorted(set(ports))
    findings = []
    mitre = []
    max_risk = "faible"
    for port in ports:
        meta = SERVICE_INTEL.get(port)
        if meta:
            label, risk, tech = meta
            findings.append(f"{port}/tcp {label} — risque {risk}")
            mitre.append(tech)
            if RISK_ORDER.get(risk, 0) > RISK_ORDER.get(max_risk, 0):
                max_risk = risk
        else:
            findings.append(f"{port}/tcp — service non classifie")
    if not findings:
        findings.append("Aucun port ouvert connu dans la session courante.")
    sev = {
        "critique": "critical",
        "haute": "high",
        "moyenne": "medium",
        "faible": "low",
    }.get(max_risk, "info")
    actions = []
    if 23 in ports:
        actions.append("Desactiver Telnet immediatement")
    if 3389 in ports:
        actions.append("RDP: NLA + restriction source / VPN")
    if 445 in ports:
        actions.append("SMB: desactiver SMBv1, patcher, isoler")
    if any(p in ports for p in (3306, 5432, 1433, 27017, 6379, 9200)):
        actions.append("Base de donnees: bind localhost ou firewall strict")
    if not actions:
        actions.append("Maintenir inventaire a jour et limiter l'exposition")
    return {
        "ok": True,
        "ip": ip,
        "hostname": host.get("hostname") or host.get("name"),
        "vendor": host.get("vendor") or host.get("oui"),
        "role": host.get("role") or host.get("type"),
        "severity": sev,
        "max_risk": max_risk,
        "ports": ports,
        "findings": findings,
        "mitre": sorted(set(mitre)),
        "priority_actions": actions,
        "remediation_url": f"/api/remediation/script/{ip}",
        "engine": "network-ai-host-v4",
        "narrative": _single_host_narrative(ip, host, ports, max_risk, findings),
        "blast": {
            "exposed_admin": any(p in ports for p in (22, 23, 3389, 5900, 5985, 5986)),
            "exposed_data": any(p in ports for p in (3306, 5432, 1433, 27017, 6379, 9200, 445)),
            "lateral_risk": any(p in ports for p in (445, 135, 139, 3389, 5985)),
        },
        "analysis_date": datetime.now().isoformat(timespec="seconds"),
    }


# --- internals -----------------------------------------------------------------

def _grade_from_score(score) -> str:
    try:
        s = float(score or 0)
    except Exception:
        return "A"
    if s >= 75:
        return "F"
    if s >= 55:
        return "D"
    if s >= 35:
        return "C"
    if s >= 20:
        return "B"
    return "A"


def _fallback_surface(arp_hosts, nmap_hosts) -> dict:
    hosts = []
    nmap_by = {h.get("ip"): h for h in nmap_hosts if h.get("ip")}
    ips = {h.get("ip") for h in arp_hosts if h.get("ip")} | set(nmap_by)
    risk_counts = {"critique": 0, "haute": 0, "moyenne": 0, "faible": 0}
    for ip in ips:
        a = next((h for h in arp_hosts if h.get("ip") == ip), {})
        n = nmap_by.get(ip, {})
        expos = []
        for p in n.get("ports") or []:
            if p.get("state") and p.get("state") != "open":
                continue
            port = int(p.get("port") or 0)
            if not port:
                continue
            meta = SERVICE_INTEL.get(port)
            risk = meta[1] if meta else "faible"
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            expos.append({"port": port, "service": (meta[0] if meta else p.get("service")), "risk": risk})
        hosts.append(
            {
                "ip": ip,
                "hostname": a.get("hostname") or n.get("hostname"),
                "vendor": a.get("vendor"),
                "role": a.get("role") or a.get("type"),
                "exposures": expos,
                "max_risk": max((e["risk"] for e in expos), key=lambda r: RISK_ORDER.get(r, 0), default="faible"),
            }
        )
    score = min(
        100,
        risk_counts["critique"] * 25
        + risk_counts["haute"] * 12
        + risk_counts["moyenne"] * 5
        + risk_counts["faible"],
    )
    return {
        "hosts": hosts,
        "total_hosts": len(hosts),
        "risk_counts": risk_counts,
        "risk_score": score,
        "grade": _grade_from_score(score),
    }


def _merge_host_context(hosts, arp_hosts, nmap_hosts) -> list:
    arp_by = {h.get("ip"): h for h in arp_hosts if h.get("ip")}
    nmap_by = {h.get("ip"): h for h in nmap_hosts if h.get("ip")}
    out = []
    seen = set()
    for h in hosts:
        ip = h.get("ip")
        if not ip:
            continue
        seen.add(ip)
        a, n = arp_by.get(ip, {}), nmap_by.get(ip, {})
        merged = {**a, **n, **h}
        if not merged.get("exposures") and n.get("ports"):
            merged["exposures"] = [
                {
                    "port": int(p["port"]),
                    "service": p.get("service"),
                    "risk": (SERVICE_INTEL.get(int(p["port"])) or (None, "faible", None))[1],
                    "product": p.get("product"),
                    "version": p.get("version"),
                }
                for p in n.get("ports") or []
                if p.get("state", "open") == "open" and p.get("port")
            ]
        out.append(merged)
    # include arp-only hosts
    for ip, a in arp_by.items():
        if ip not in seen:
            out.append(a)
    return out


def _port_statistics(hosts: list) -> list[dict]:
    c = Counter()
    for h in hosts:
        for e in h.get("exposures") or []:
            if isinstance(e, dict) and e.get("port"):
                c[int(e["port"])] += 1
        for p in h.get("open_ports") or []:
            try:
                c[int(p if not isinstance(p, dict) else p.get("port"))] += 1
            except Exception:
                pass
    rows = []
    for port, count in c.most_common(20):
        meta = SERVICE_INTEL.get(port)
        rows.append(
            {
                "port": port,
                "count": count,
                "service": meta[0] if meta else "?",
                "risk": meta[1] if meta else "unknown",
            }
        )
    return rows


def _hot_hosts(hosts: list) -> list[dict]:
    ranked = []
    for h in hosts:
        exposures = h.get("exposures") or []
        risks = [e.get("risk") for e in exposures if isinstance(e, dict)]
        max_risk = h.get("max_risk")
        if not max_risk and risks:
            max_risk = max(risks, key=lambda r: RISK_ORDER.get(r or "unknown", 0))
        score = sum(RISK_ORDER.get(r or "unknown", 0) for r in risks) * 10
        score += RISK_ORDER.get(max_risk or "unknown", 0) * 15
        if score <= 0 and max_risk not in ("critique", "haute"):
            continue
        ranked.append(
            {
                "ip": h.get("ip"),
                "hostname": h.get("hostname") or h.get("name"),
                "vendor": h.get("vendor") or h.get("oui"),
                "role": h.get("role") or h.get("type"),
                "max_risk": max_risk or "unknown",
                "score": score,
                "exposure_count": len(exposures),
                "top_ports": [
                    e.get("port")
                    for e in exposures
                    if isinstance(e, dict) and e.get("risk") in ("critique", "haute")
                ][:8],
                "exposures": [
                    {
                        "port": e.get("port"),
                        "service": e.get("service"),
                        "risk": e.get("risk"),
                        "product": e.get("product"),
                    }
                    for e in exposures[:8]
                    if isinstance(e, dict)
                ],
            }
        )
    ranked.sort(key=lambda x: (-x["score"], x.get("ip") or ""))
    return ranked[:12]


def _insecure_findings(hosts: list) -> list[dict]:
    out = []
    for h in hosts:
        ip = h.get("ip")
        for e in h.get("exposures") or []:
            if not isinstance(e, dict):
                continue
            port = e.get("port")
            try:
                port = int(port)
            except Exception:
                continue
            meta = SERVICE_INTEL.get(port)
            risk = e.get("risk") or (meta[1] if meta else "faible")
            if risk not in ("critique", "haute"):
                continue
            out.append(
                {
                    "ip": ip,
                    "hostname": h.get("hostname"),
                    "port": port,
                    "service": e.get("service") or (meta[0] if meta else "?"),
                    "risk": risk,
                    "product": e.get("product") or "",
                    "version": e.get("version") or "",
                    "mitre": meta[2] if meta else "T1046",
                    "recommendation": e.get("recommendation")
                    or _rec_for_port(port),
                }
            )
    out.sort(key=lambda x: (-RISK_ORDER.get(x["risk"], 0), x.get("ip") or ""))
    return out


def _rec_for_port(port: int) -> str:
    recs = {
        23: "Desactiver Telnet immediatement (clair).",
        21: "Remplacer FTP par SFTP/FTPS.",
        445: "SMBv1 off, patcher, ne pas exposer hors LAN.",
        3389: "RDP: NLA + allowlist + VPN, jamais Internet.",
        5900: "VNC: tunnel SSH ou desactiver.",
        3306: "MySQL: bind 127.0.0.1 + firewall.",
        5432: "PostgreSQL: restreindre aux admins.",
        1433: "MSSQL: pas d'exposition directe.",
        6379: "Redis: auth + bind localhost.",
        27017: "MongoDB: auth + reseau prive.",
        9200: "Elasticsearch: ne jamais exposer sans auth TLS.",
        2375: "Docker API: TLS + pas de 2375 en clair.",
        22: "SSH: cles only, fail2ban, PermitRootLogin no.",
        161: "SNMP: v3 only, community par defaut interdite.",
    }
    return recs.get(port, "Restreindre l'acces reseau et auditer le service.")


def _mitre_map(insecure: list, risk_counts: dict) -> list[str]:
    techs = set()
    if risk_counts.get("critique") or risk_counts.get("haute"):
        techs.add("T1046")
    for f in insecure:
        if f.get("mitre"):
            techs.add(f["mitre"])
    return sorted(techs)


def _severity(grade, risk_score, risk_counts, insecure) -> str:
    crit = risk_counts.get("critique", 0)
    high = risk_counts.get("haute", 0)
    if grade in ("F", "D") or risk_score >= 75 or crit >= 3:
        return "critical"
    if grade == "C" or risk_score >= 45 or crit >= 1 or high >= 5 or len(insecure) >= 8:
        return "high"
    if grade == "B" or risk_score >= 25 or high >= 1:
        return "medium"
    return "low"


def _summary(severity, grade, risk_score, total_hosts, risk_counts, snap) -> str:
    subnet = (snap or {}).get("subnet") or "reseau local"
    ssid = (snap or {}).get("ssid")
    wifi = f" (Wi‑Fi {ssid})" if ssid else ""
    base = f"Analyse de {total_hosts} hote(s) sur {subnet}{wifi}. Grade {grade}, score d'exposition {risk_score}/100."
    if severity == "critical":
        return (
            f"{base} Exposition CRITIQUE: {risk_counts.get('critique', 0)} service(s) critique(s), "
            f"{risk_counts.get('haute', 0)} a risque eleve. Remediation immediate requise."
        )
    if severity == "high":
        return (
            f"{base} Exposition ELEVEE: services sensibles visibles. "
            "Prioriser le durcissement et la segmentation."
        )
    if severity == "medium":
        return (
            f"{base} Exposition MODEREE. Quelques services a securiser; "
            "maintenir scans et politique de ports."
        )
    return (
        f"{base} Posture globalement saine. Continuer monitoring ARP/Watch "
        "et revues periodiques."
    )


def _priority_actions(severity, risk_counts, total_hosts, insecure, hot_hosts, intel, port_stats):
    actions = []
    if risk_counts.get("critique", 0):
        actions.append(
            f"Neutraliser {risk_counts['critique']} service(s) critique(s) "
            f"(ex: {', '.join(str(i['port']) for i in insecure[:4] if i.get('risk')=='critique') or 'RDP/SMB/Telnet/DB'})."
        )
    if risk_counts.get("haute", 0):
        actions.append(f"Plan de patch/durcissement pour {risk_counts['haute']} service(s) a risque eleve.")
    if any(i["port"] == 23 for i in insecure):
        actions.append("Telnet detecte — desactivation urgente.")
    if any(i["port"] == 3389 for i in insecure):
        actions.append("RDP expose — NLA + restriction source + journalisation.")
    if any(i["port"] == 445 for i in insecure):
        actions.append("SMB expose — SMBv1 off, isolation VLAN, audits shares.")
    if total_hosts > 40:
        actions.append(f"Segmentation recommandee ({total_hosts} hotes visibles).")
    if intel.get("anomaly_count"):
        actions.append(f"Investiguer {intel['anomaly_count']} anomalie(s) ML Intel.")
    if hot_hosts:
        ips = ", ".join(h["ip"] for h in hot_hosts[:3] if h.get("ip"))
        actions.append(f"Focus hotes prioritaires: {ips}.")
    # top risky port proliferation
    for ps in port_stats[:3]:
        if ps.get("risk") in ("critique", "haute") and ps.get("count", 0) >= 3:
            actions.append(
                f"Port {ps['port']}/{ps.get('service')} present sur {ps['count']} hotes — standardiser le controle d'acces."
            )
            break
    if not actions:
        actions.append("Maintenir Watch/ARP periodique + export rapport baseline.")
        actions.append("Lancer Policy (:8085) pour score de conformite.")
    return actions[:10]


def _quick_wins(insecure: list) -> list[str]:
    wins = []
    ports = {i["port"] for i in insecure}
    if 23 in ports:
        wins.append("Couper Telnet (systemctl disable --now telnet || equiv.)")
    if 21 in ports:
        wins.append("Migrer FTP → SFTP")
    if 5900 in ports:
        wins.append("Restreindre VNC ou forcer tunnel SSH")
    if 2375 in ports:
        wins.append("Fermer Docker API 2375 non TLS")
    if 6379 in ports or 9200 in ports or 27017 in ports:
        wins.append("Bind DB/cache sur localhost + auth")
    if 3389 in ports:
        wins.append("RDP derriere VPN / allowlist firewall")
    if not wins:
        wins.append("Revue firewall host + desactiver services inutiles")
    return wins[:6]


def _posture_checklist(hosts, snap, risk_counts) -> dict:
    checks = []
    checks.append({"id": "inventory", "ok": len(hosts) > 0, "label": "Inventaire hotes disponible"})
    checks.append(
        {
            "id": "no_telnet",
            "ok": not any(
                (e.get("port") == 23)
                for h in hosts
                for e in (h.get("exposures") or [])
                if isinstance(e, dict)
            ),
            "label": "Aucun Telnet (23) ouvert",
        }
    )
    checks.append(
        {
            "id": "no_crit_many",
            "ok": risk_counts.get("critique", 0) == 0,
            "label": "Zero service critique expose",
        }
    )
    checks.append(
        {
            "id": "gateway_known",
            "ok": bool((snap or {}).get("gateway")),
            "label": "Passerelle identifiee",
        }
    )
    checks.append(
        {
            "id": "subnet_known",
            "ok": bool((snap or {}).get("subnet")),
            "label": "Subnet local connu",
        }
    )
    ok_n = sum(1 for c in checks if c["ok"])
    return {"score": int(100 * ok_n / max(1, len(checks))), "checks": checks}


def _call_external_ai(summary: dict) -> Optional[dict[str, Any]]:
    """Best-effort call to harmattan-ai network-summary / analyze."""
    try:
        import os
        from pathlib import Path

        import requests

        base = os.environ.get("HARMATTAN_AI_URL", "http://127.0.0.1:8110").rstrip("/")
        tok = os.environ.get("AI_TOKEN", "").strip()
        p = Path.home() / "harmattan-ai/data/.api_token"
        if not tok and p.is_file():
            tok = p.read_text(encoding="utf-8").strip()
        headers = {"Content-Type": "application/json"}
        if tok:
            headers["X-AI-Token"] = tok
        # Prefer structured text for rules engine
        text = (
            f"Network grade {summary.get('grade')} score {summary.get('risk_score')} "
            f"severity {summary.get('severity')} hosts {summary.get('total_hosts')} "
            f"critiques {summary.get('risk_counts', {}).get('critique')} "
            f"actions: {'; '.join(summary.get('priority_actions') or [])} "
            f"paths: {'; '.join(p.get('name','') for p in (summary.get('attack_paths') or [])[:3])}"
        )
        r = requests.post(
            f"{base}/api/analyze",
            json={"text": text, "llm": os.environ.get("HARMATTAN_AI_LLM", "0") in ("1", "true"), "cortex": False},
            headers=headers,
            timeout=20,
        )
        if r.status_code < 400:
            body = r.json()
            return {
                "ok": True,
                "source": "harmattan-ai",
                "severity": (body.get("analysis") or {}).get("severity"),
                "findings": (body.get("analysis") or {}).get("findings"),
                "playbook": body.get("playbook"),
            }
    except Exception as e:
        return {"ok": False, "error": str(e)[:120]}
    return None


# --- AI v4 extras -------------------------------------------------------------

def _executive_brief(severity, grade, score, total_hosts, risk_counts, snap, hot, insecure) -> str:
    subnet = (snap or {}).get("subnet") or "segment local"
    ssid = (snap or {}).get("ssid")
    loc = f"SSID « {ssid} » / " if ssid else ""
    crit = risk_counts.get("critique", 0)
    high = risk_counts.get("haute", 0)
    top = ", ".join(
        f"{h.get('ip')}({h.get('max_risk')})" for h in (hot or [])[:3] if h.get("ip")
    ) or "—"
    ports = ", ".join(str(i.get("port")) for i in (insecure or [])[:5]) or "aucun"
    return (
        f"Brief exécutif — {loc}{subnet}. "
        f"{total_hosts} hôte(s) inventorié(s), grade {grade} (score {score}/100), "
        f"sévérité {severity}. "
        f"Expositions critiques: {crit}, hautes: {high}. "
        f"Hôtes prioritaires: {top}. "
        f"Services sensibles observés: {ports}. "
        f"{'Action immédiate requise sur les services critiques.' if crit else 'Maintenir la pression de durcissement et le monitoring.'}"
    )


def _confidence(hosts, arp_hosts, nmap_hosts, attack) -> dict:
    score = 35
    if arp_hosts or hosts:
        score += 25
    if nmap_hosts:
        score += 25
    if attack and attack.get("hosts"):
        score += 10
    if any((h.get("exposures") for h in (hosts or []))):
        score += 5
    score = min(98, score)
    level = "high" if score >= 75 else "medium" if score >= 50 else "low"
    return {
        "score": score,
        "level": level,
        "basis": {
            "has_arp": bool(arp_hosts or hosts),
            "has_nmap": bool(nmap_hosts),
            "has_attack_surface": bool(attack and attack.get("hosts")),
        },
        "note": "Confiance élevée si ARP+nmap présents; faible si inventaire partiel.",
    }


def _attack_paths(hosts, snap) -> list[dict]:
    paths = []
    gw = (snap or {}).get("gateway")
    has_smb = any(
        e.get("port") == 445 for h in hosts for e in (h.get("exposures") or []) if isinstance(e, dict)
    )
    has_rdp = any(
        e.get("port") == 3389 for h in hosts for e in (h.get("exposures") or []) if isinstance(e, dict)
    )
    has_telnet = any(
        e.get("port") == 23 for h in hosts for e in (h.get("exposures") or []) if isinstance(e, dict)
    )
    has_db = any(
        e.get("port") in (3306, 5432, 1433, 27017, 6379)
        for h in hosts
        for e in (h.get("exposures") or [])
        if isinstance(e, dict)
    )
    if has_telnet:
        paths.append({
            "id": "P1",
            "name": "Accès clair-text Telnet",
            "severity": "critical",
            "steps": ["Internet/LAN → hôte:23 Telnet", "Credential sniff / brute", "Pivot interne"],
            "mitre": ["T1021", "T1110"],
        })
    if has_rdp:
        paths.append({
            "id": "P2",
            "name": "Exposition RDP",
            "severity": "critical",
            "steps": ["Scan RDP 3389", "Brute / exploit", "Contrôle poste + latéral"],
            "mitre": ["T1021.001", "T1110"],
        })
    if has_smb:
        paths.append({
            "id": "P3",
            "name": "Mouvement latéral SMB",
            "severity": "high",
            "steps": ["Enum shares 445", "Creds réutilisés", "Propagation domaine/workgroup"],
            "mitre": ["T1021.002", "T1080"],
        })
    if has_db:
        paths.append({
            "id": "P4",
            "name": "Accès données exposées",
            "severity": "critical",
            "steps": ["DB/cache ouverte", "Extraction données", "Exfiltration"],
            "mitre": ["T1210", "T1041"],
        })
    if gw:
        paths.append({
            "id": "P5",
            "name": "Compromission passerelle",
            "severity": "high",
            "steps": [f"Cible gateway {gw}", "Admin web / SNMP faible", "MITM / DNS hijack LAN"],
            "mitre": ["T1557", "T1040"],
        })
    if not paths:
        paths.append({
            "id": "P0",
            "name": "Surface limitée",
            "severity": "low",
            "steps": ["Peu de services sensibles détectés dans la session"],
            "mitre": [],
        })
    return paths[:6]


def _blast_radius(hosts, insecure, hot) -> dict:
    crit_hosts = {h.get("ip") for h in (hot or []) if h.get("max_risk") in ("critique", "haute")}
    admin_ports = sum(1 for i in insecure if i.get("port") in (22, 23, 3389, 5900, 5985))
    data_ports = sum(1 for i in insecure if i.get("port") in (445, 3306, 5432, 1433, 27017, 6379))
    return {
        "hosts_high_risk": len(crit_hosts),
        "admin_exposures": admin_ports,
        "data_exposures": data_ports,
        "estimated_impact": (
            "élevé" if admin_ports + data_ports >= 5 or len(crit_hosts) >= 3
            else "modéré" if admin_ports or data_ports else "faible"
        ),
        "note": "Estimation heuristique basée sur ports admin/données et hôtes prioritaires.",
    }


def _segmentation_plan(hosts, role_stats, risk_counts) -> list[str]:
    plan = []
    iot = role_stats.get("iot", 0) + role_stats.get("camera", 0) + role_stats.get("tv", 0)
    if iot:
        plan.append(f"Isoler {iot} device(s) IoT/caméra/TV sur VLAN invité sans accès LAN admin.")
    if role_stats.get("printer", 0):
        plan.append("Imprimantes: VLAN print + ACL (pas d'accès Internet sortant inutile).")
    if risk_counts.get("critique", 0):
        plan.append("Placer hôtes à services critiques derrière bastion / jump host.")
    if role_stats.get("server", 0) or role_stats.get("vm", 0):
        plan.append("Serveurs/VM: segment dédié + micro-segmentation east-west.")
    if not plan:
        plan.append("Conserver flat LAN uniquement si petit lab; sinon préparer VLAN management.")
    plan.append("Gateway: désactiver admin WAN, SNMP public, UPnP si non requis.")
    return plan[:6]


def _remediation_sla(risk_counts, severity) -> list[dict]:
    sla = []
    if risk_counts.get("critique", 0):
        sla.append({"severity": "critique", "deadline": "24h", "action": "Fermer/isoler services critiques"})
    if risk_counts.get("haute", 0):
        sla.append({"severity": "haute", "deadline": "7j", "action": "Patch + durcissement + ACL"})
    if risk_counts.get("moyenne", 0):
        sla.append({"severity": "moyenne", "deadline": "30j", "action": "Revue config + least privilege"})
    sla.append({"severity": "hygiene", "deadline": "continu", "action": "Monitor ARP + scans planifiés"})
    if severity in ("critical", "high") and not risk_counts.get("critique"):
        sla.insert(0, {"severity": "haute", "deadline": "48h", "action": "Réduire surface globale"})
    return sla


def _risk_matrix(hosts) -> dict:
    """Count hosts by max exposure severity for matrix display."""
    matrix = {"critique": 0, "haute": 0, "moyenne": 0, "faible": 0, "none": 0}
    for h in hosts or []:
        mr = (h.get("max_risk") or "none").lower()
        if mr in matrix:
            matrix[mr] += 1
        elif not (h.get("exposures") or h.get("open_ports")):
            matrix["none"] += 1
        else:
            matrix["faible"] += 1
    return matrix


def _host_narratives(hot_hosts: list) -> list[dict]:
    out = []
    for h in hot_hosts or []:
        ip = h.get("ip") or "?"
        risk = h.get("max_risk") or "—"
        ports = h.get("ports") or h.get("open_ports") or []
        if ports and isinstance(ports[0], dict):
            ports = [p.get("port") for p in ports]
        port_s = ", ".join(str(p) for p in list(ports)[:8]) or "—"
        role = h.get("role") or "host"
        out.append({
            "ip": ip,
            "role": role,
            "max_risk": risk,
            "text": (
                f"{ip} ({role}) présente un risque {risk}. "
                f"Ports observés: {port_s}. "
                f"{'Prioriser isolation et audit credentials.' if risk in ('critique','haute') else 'Surveiller et documenter.'}"
            ),
        })
    return out


def _single_host_narrative(ip, host, ports, max_risk, findings) -> str:
    role = host.get("role") or "inconnu"
    vendor = host.get("vendor") or "—"
    return (
        f"Hôte {ip} classé « {role} » (vendor {vendor}). "
        f"Risque max {max_risk}. "
        f"{len(ports)} port(s) analysé(s). "
        f"{findings[0] if findings else 'Pas de finding détaillé.'}"
    )
