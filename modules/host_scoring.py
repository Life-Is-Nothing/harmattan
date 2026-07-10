"""
HARMATTAN — Host anomaly scoring (IsolationForest if sklearn, else heuristic).
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Any

from core.logging_setup import get_logger

log = get_logger("harmattan.scoring")

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest

    HAS_SKLEARN = True
except Exception:
    HAS_SKLEARN = False


SENSITIVE = {23, 445, 3389, 1433, 5900, 21, 135, 139, 161, 3306, 5432, 554}


def _open_ports(h: dict, nmap_by_ip: dict) -> list[int]:
    ports = []
    n = nmap_by_ip.get(h.get("ip") or "", {})
    for p in n.get("ports") or []:
        if p.get("state") == "open":
            try:
                ports.append(int(p["port"]))
            except (TypeError, ValueError):
                pass
    for p in h.get("open_ports") or []:
        try:
            ports.append(int(p if not isinstance(p, dict) else p.get("port")))
        except (TypeError, ValueError):
            pass
    return sorted(set(ports))


def _features(hosts: list[dict], nmap_hosts: list[dict]) -> tuple[list[list[float]], list[dict]]:
    nmap_by_ip = {h.get("ip"): h for h in nmap_hosts if h.get("ip")}
    role_ids = {}
    vendor_ids = {}
    rows = []
    meta = []
    for h in hosts:
        ip = h.get("ip") or ""
        if not ip:
            continue
        ports = _open_ports(h, nmap_by_ip)
        role = (h.get("role") or "unknown").lower()
        vendor = (h.get("vendor") or "unknown").lower()[:40]
        if role not in role_ids:
            role_ids[role] = len(role_ids)
        if vendor not in vendor_ids:
            vendor_ids[vendor] = len(vendor_ids)
        sens = sum(1 for p in ports if p in SENSITIVE)
        feat = [
            float(len(ports)),
            float(sens),
            float(max(ports) if ports else 0) / 65535.0,
            float(role_ids[role]),
            float(vendor_ids[vendor] % 50),
            1.0 if h.get("role_override") else 0.0,
            1.0 if role in ("camera", "iot", "printer") else 0.0,
            1.0 if any(p in (23, 445, 3389) for p in ports) else 0.0,
        ]
        rows.append(feat)
        meta.append(
            {
                "ip": ip,
                "mac": h.get("mac"),
                "role": role,
                "vendor": h.get("vendor"),
                "hostname": h.get("hostname"),
                "ports": ports,
                "sensitive_ports": [p for p in ports if p in SENSITIVE],
            }
        )
    return rows, meta


def _heuristic_scores(X: list[list[float]]) -> list[float]:
    """Higher = more anomalous (0–100)."""
    if not X:
        return []
    cols = list(zip(*X))
    means = [sum(c) / len(c) for c in cols]
    stds = []
    for c, m in zip(cols, means):
        var = sum((v - m) ** 2 for v in c) / max(1, len(c))
        stds.append(math.sqrt(var) or 1.0)
    scores = []
    for row in X:
        z = sum(abs(v - m) / s for v, m, s in zip(row, means, stds))
        # sensitive ports heavily weighted (index 1 and 7)
        bonus = row[1] * 8 + row[7] * 15 + row[6] * 5
        scores.append(min(100.0, z * 6 + bonus))
    return scores


def score_hosts(arp_hosts: list | None = None, nmap_hosts: list | None = None) -> dict:
    arp_hosts = arp_hosts or []
    nmap_hosts = nmap_hosts or []
    X, meta = _features(arp_hosts, nmap_hosts)
    if len(X) < 2:
        return {
            "ok": True,
            "method": "insufficient_data",
            "hosts": [
                {**m, "anomaly_score": 0, "label": "normal", "reasons": ["pas assez d'hôtes"]}
                for m in meta
            ],
            "anomalies": [],
            "sklearn": HAS_SKLEARN,
        }

    method = "heuristic"
    raw_scores: list[float]
    labels: list[str] = []

    if HAS_SKLEARN and len(X) >= 3:
        try:
            arr = np.array(X, dtype=float)
            clf = IsolationForest(
                n_estimators=100,
                contamination="auto",
                random_state=42,
            )
            pred = clf.fit_predict(arr)  # -1 anomaly
            decision = clf.decision_function(arr)  # higher = more normal
            # invert to 0–100 anomaly
            raw_scores = [float(max(0, min(100, (-d + 0.5) * 80))) for d in decision]
            labels = ["anomaly" if p == -1 else "normal" for p in pred]
            method = "isolation_forest"
        except Exception as e:
            log.warning("IsolationForest failed: %s", e)
            raw_scores = _heuristic_scores(X)
            labels = ["anomaly" if s >= 45 else "normal" for s in raw_scores]
    else:
        raw_scores = _heuristic_scores(X)
        labels = ["anomaly" if s >= 45 else "normal" for s in raw_scores]

    hosts_out = []
    for m, sc, lab in zip(meta, raw_scores, labels):
        reasons = []
        if m["sensitive_ports"]:
            reasons.append("ports sensibles: " + ",".join(map(str, m["sensitive_ports"])))
        if len(m["ports"]) >= 8:
            reasons.append(f"beaucoup de ports ouverts ({len(m['ports'])})")
        if m["role"] in ("camera", "iot"):
            reasons.append(f"rôle à risque: {m['role']}")
        if lab == "anomaly" and not reasons:
            reasons.append("profil statistique atypique")
        hosts_out.append(
            {
                **m,
                "anomaly_score": round(sc, 1),
                "label": lab,
                "reasons": reasons,
            }
        )
    hosts_out.sort(key=lambda x: -x["anomaly_score"])
    anomalies = [h for h in hosts_out if h["label"] == "anomaly" or h["anomaly_score"] >= 45]
    return {
        "ok": True,
        "method": method,
        "sklearn": HAS_SKLEARN,
        "host_count": len(hosts_out),
        "anomaly_count": len(anomalies),
        "hosts": hosts_out,
        "anomalies": anomalies[:30],
    }
