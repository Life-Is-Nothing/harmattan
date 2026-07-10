"""
HARMATTAN — Map findings to MITRE ATT&CK techniques (defensive coverage view).
"""
from __future__ import annotations

# Port / signal → ATT&CK technique(s)
PORT_TECHNIQUES = {
    21: [("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
         ("T1071", "Application Layer Protocol", "C2")],
    22: [("T1021.004", "Remote Services: SSH", "Lateral Movement")],
    23: [("T1021", "Remote Services", "Lateral Movement"),
         ("T1040", "Network Sniffing", "Credential Access")],
    25: [("T1071.003", "Application Layer Protocol: Mail", "C2")],
    53: [("T1071.004", "Application Layer Protocol: DNS", "C2"),
         ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration")],
    80: [("T1071.001", "Application Layer Protocol: Web", "C2"),
         ("T1190", "Exploit Public-Facing Application", "Initial Access")],
    135: [("T1021.003", "Remote Services: Distributed Component Object Model", "Lateral Movement")],
    139: [("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement")],
    161: [("T1040", "Network Sniffing", "Credential Access"),
          ("T1005", "Data from Local System", "Collection")],
    443: [("T1071.001", "Application Layer Protocol: Web", "C2"),
          ("T1573", "Encrypted Channel", "C2")],
    445: [("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
          ("T1486", "Data Encrypted for Impact", "Impact")],
    554: [("T1125", "Video Capture", "Collection")],
    1433: [("T1505.001", "Server Software Component: SQL Stored Procedures", "Persistence")],
    1883: [("T1071", "Application Layer Protocol", "C2")],
    3306: [("T1505.001", "Server Software Component: SQL Stored Procedures", "Persistence")],
    3389: [("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement")],
    5432: [("T1505.001", "Server Software Component: SQL Stored Procedures", "Persistence")],
    5900: [("T1021", "Remote Services", "Lateral Movement")],
    8080: [("T1190", "Exploit Public-Facing Application", "Initial Access")],
}

ROLE_TECHNIQUES = {
    "camera": [("T1125", "Video Capture", "Collection"),
               ("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "iot": [("T1200", "Hardware Additions", "Initial Access"),
            ("T0883", "Internet Accessible Device", "ICS")],
    "printer": [("T1040", "Network Sniffing", "Credential Access")],
    "server": [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "ap": [("T1557", "Adversary-in-the-Middle", "Credential Access")],
    "gateway": [("T1557", "Adversary-in-the-Middle", "Credential Access"),
                ("T1040", "Network Sniffing", "Credential Access")],
}

NEW_DEVICE = [("T1200", "Hardware Additions", "Initial Access"),
              ("T0883", "Internet Accessible Device", "ICS")]


def _add(bucket: dict, tid: str, name: str, tactic: str, evidence: str, ip: str = ""):
    if tid not in bucket:
        bucket[tid] = {
            "technique_id": tid,
            "technique": name,
            "tactic": tactic,
            "count": 0,
            "evidence": [],
            "hosts": set(),
        }
    bucket[tid]["count"] += 1
    if evidence and len(bucket[tid]["evidence"]) < 12:
        bucket[tid]["evidence"].append(evidence)
    if ip:
        bucket[tid]["hosts"].add(ip)


def map_network(
    arp_hosts: list | None = None,
    nmap_hosts: list | None = None,
    attack: dict | None = None,
    new_devices: list | None = None,
) -> dict:
    arp_hosts = arp_hosts or []
    nmap_hosts = nmap_hosts or []
    attack = attack or {}
    new_devices = new_devices or []
    tech: dict = {}

    nmap_by_ip = {h.get("ip"): h for h in nmap_hosts if h.get("ip")}

    for h in arp_hosts:
        ip = h.get("ip") or ""
        role = (h.get("role") or "").lower()
        for tid, name, tactic in ROLE_TECHNIQUES.get(role, []):
            _add(tech, tid, name, tactic, f"role={role}", ip)

    for h in nmap_hosts:
        ip = h.get("ip") or ""
        for p in h.get("ports") or []:
            if p.get("state") and p.get("state") != "open":
                continue
            try:
                port = int(p.get("port"))
            except (TypeError, ValueError):
                continue
            for tid, name, tactic in PORT_TECHNIQUES.get(port, []):
                svc = p.get("service") or ""
                _add(tech, tid, name, tactic, f"{ip}:{port}/{svc}", ip)

    # also from attack surface exposures
    for exp in attack.get("exposures") or []:
        try:
            port = int(exp.get("port"))
        except (TypeError, ValueError):
            continue
        ip = exp.get("ip") or ""
        for tid, name, tactic in PORT_TECHNIQUES.get(port, []):
            _add(tech, tid, name, tactic, f"exposure {ip}:{port}", ip)

    for h in attack.get("hosts") or []:
        ip = h.get("ip") or ""
        for exp in h.get("exposures") or []:
            try:
                port = int(exp.get("port"))
            except (TypeError, ValueError):
                continue
            for tid, name, tactic in PORT_TECHNIQUES.get(port, []):
                _add(tech, tid, name, tactic, f"{ip}:{port}", ip)

    for nd in new_devices:
        ip = nd.get("ip") or ""
        for tid, name, tactic in NEW_DEVICE:
            _add(tech, tid, name, tactic, f"new device {nd.get('mac') or ip}", ip)

    techniques = []
    for t in tech.values():
        techniques.append(
            {
                "technique_id": t["technique_id"],
                "technique": t["technique"],
                "tactic": t["tactic"],
                "count": t["count"],
                "hosts": sorted(t["hosts"]),
                "host_count": len(t["hosts"]),
                "evidence": t["evidence"],
            }
        )
    techniques.sort(key=lambda x: (-x["count"], x["technique_id"]))

    tactics: dict[str, int] = {}
    for t in techniques:
        tactics[t["tactic"]] = tactics.get(t["tactic"], 0) + t["count"]

    return {
        "framework": "MITRE ATT&CK",
        "version_note": "enterprise + ICS subset (defensive mapping)",
        "technique_count": len(techniques),
        "techniques": techniques,
        "tactics": tactics,
        "coverage_hint": (
            "Ce mapping relie surface d'attaque locale aux techniques ATT&CK "
            "pour prioriser détection / segmentation — pas un scan offensif."
        ),
    }
