"""
HARMATTAN — STIX 2.1 bundle export (pure JSON, no stix2 dependency).
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _id(typ: str, seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()[:24]
    return f"{typ}--{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:24]}000000"


def build_bundle(
    arp_hosts: list | None = None,
    nmap_hosts: list | None = None,
    mitre: dict | None = None,
    version: str = "3.2.0",
) -> dict[str, Any]:
    arp_hosts = arp_hosts or []
    nmap_hosts = nmap_hosts or []
    mitre = mitre or {}
    now = _now()
    objects: list[dict] = []

    identity_id = _id("identity", "harmattan-nacf")
    objects.append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "HARMATTAN Network Intelligence",
            "identity_class": "organization",
            "description": f"Export HARMATTAN v{version}",
        }
    )

    nmap_by_ip = {h.get("ip"): h for h in nmap_hosts if h.get("ip")}
    host_ids = {}

    for h in arp_hosts:
        ip = h.get("ip")
        if not ip:
            continue
        seed = f"{ip}|{h.get('mac') or ''}"
        hid = _id("infrastructure", seed)
        host_ids[ip] = hid
        ports = []
        nh = nmap_by_ip.get(ip) or {}
        for p in nh.get("ports") or []:
            if p.get("state") == "open":
                ports.append(int(p["port"]))
        objects.append(
            {
                "type": "infrastructure",
                "spec_version": "2.1",
                "id": hid,
                "created": now,
                "modified": now,
                "name": h.get("hostname") or ip,
                "infrastructure_types": [h.get("role") or "unknown"],
                "description": (
                    f"MAC={h.get('mac') or '?'} vendor={h.get('vendor') or '?'} "
                    f"ports={ports}"
                ),
            }
        )
        # observable as separate note-like custom — use observed-data
        oid = _id("observed-data", seed + "-obs")
        objects.append(
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": oid,
                "created": now,
                "modified": now,
                "first_observed": now,
                "last_observed": now,
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "ipv4-addr",
                        "value": ip,
                    },
                    **(
                        {
                            "1": {
                                "type": "mac-addr",
                                "value": (h.get("mac") or "").lower(),
                            }
                        }
                        if h.get("mac")
                        else {}
                    ),
                },
            }
        )

    # indicators for sensitive exposures
    for h in nmap_hosts:
        ip = h.get("ip")
        for p in h.get("ports") or []:
            if p.get("state") != "open":
                continue
            try:
                port = int(p["port"])
            except (TypeError, ValueError):
                continue
            if port not in (23, 445, 3389, 21, 5900, 1433):
                continue
            iid = _id("indicator", f"{ip}:{port}")
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": iid,
                    "created": now,
                    "modified": now,
                    "name": f"Exposed service {ip}:{port}",
                    "description": f"Service {p.get('service') or 'unknown'} open on audit network",
                    "indicator_types": ["anomalous-activity"],
                    "pattern": f"[network-traffic:dst_ref.value = '{ip}' AND network-traffic:dst_port = {port}]",
                    "pattern_type": "stix",
                    "valid_from": now,
                    "created_by_ref": identity_id,
                }
            )

    for t in (mitre.get("techniques") or [])[:40]:
        tid = t.get("technique_id") or ""
        if not tid:
            continue
        aid = _id("attack-pattern", tid)
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": aid,
                "created": now,
                "modified": now,
                "name": t.get("technique") or tid,
                "description": f"Mapped from local findings ({t.get('count')} evidence)",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tid,
                        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                    }
                ],
            }
        )

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }
