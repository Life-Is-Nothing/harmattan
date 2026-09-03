"""
HARMATTAN — Export findings / hosts as MISP-like event JSON (offline).
Compatible with MISP import (simplified event structure).
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any


def build_misp_event(
    *,
    hosts: list[dict] | None = None,
    attack: dict | None = None,
    findings: list[dict] | None = None,
    iocs: list[dict] | None = None,
    org: str = "HARMATTAN",
    info: str = "HARMATTAN network audit export",
    threat_level_id: str = "3",
) -> dict[str, Any]:
    """Build a MISP Event JSON structure (simplified, no signing)."""
    hosts = hosts or []
    attack = attack or {}
    findings = findings or []
    iocs = iocs or []
    now = datetime.utcnow().strftime("%Y-%m-%d")
    event_uuid = str(uuid.uuid4())
    attributes: list[dict] = []

    def _attr(atype: str, value: str, category: str = "Network activity", comment: str = "", to_ids: bool = False):
        if not value:
            return
        attributes.append({
            "type": atype,
            "category": category,
            "value": str(value)[:500],
            "to_ids": to_ids,
            "comment": comment[:500],
            "uuid": str(uuid.uuid4()),
            "timestamp": str(int(datetime.utcnow().timestamp())),
        })

    for h in hosts:
        ip = h.get("ip")
        mac = h.get("mac")
        if ip:
            _attr("ip-dst", ip, "Network activity", f"host {h.get('hostname') or ''} role={h.get('role') or ''}")
        if mac:
            _attr("mac-address", mac, "Network activity", h.get("vendor") or "")

    for h in attack.get("hosts") or []:
        for e in h.get("exposures") or []:
            risk = e.get("risk") or ""
            to_ids = risk in ("critique", "haute", "critical", "high")
            port = e.get("port")
            if h.get("ip") and port:
                _attr(
                    "ip-dst|port",
                    f"{h['ip']}|{port}",
                    "Network activity",
                    f"{e.get('service') or ''} {risk} {e.get('recommendation') or ''}",
                    to_ids=to_ids,
                )

    for f in findings:
        title = f.get("title") or "finding"
        detail = f.get("detail") or ""
        _attr("text", f"{title}: {detail}"[:400], "Other", f.get("severity") or "info")

    for ioc in iocs:
        itype = (ioc.get("type") or "ip").lower()
        val = ioc.get("value") or ""
        mapping = {
            "ip": "ip-dst",
            "domain": "domain",
            "url": "url",
            "hash": "sha256" if len(val) == 64 else "md5" if len(val) == 32 else "filename|md5",
            "email": "email-src",
        }
        _attr(mapping.get(itype, "text"), val, "Network activity", ",".join(ioc.get("tags") or []), to_ids=True)

    event = {
        "Event": {
            "uuid": event_uuid,
            "info": info,
            "date": now,
            "threat_level_id": str(threat_level_id),
            "analysis": "1",
            "distribution": "0",
            "Orgc": {"name": org},
            "Attribute": attributes,
            "Tag": [{"name": "harmattan:export"}, {"name": "tlp:amber"}],
            "publish_timestamp": str(int(datetime.utcnow().timestamp())),
            "timestamp": str(int(datetime.utcnow().timestamp())),
            "Attribute_count": str(len(attributes)),
        }
    }
    # stable-ish id from content
    digest = hashlib.sha256(event_uuid.encode()).hexdigest()[:8]
    event["Event"]["id"] = digest
    return event


def build_elastic_bulk(
    *,
    hosts: list[dict] | None = None,
    attack: dict | None = None,
    index: str = "harmattan-assets",
) -> str:
    """NDJSON bulk body for Elasticsearch / OpenSearch."""
    hosts = hosts or []
    attack = attack or {}
    attack_by_ip = {h.get("ip"): h for h in (attack.get("hosts") or [])}
    lines: list[str] = []
    import json

    now = datetime.utcnow().isoformat() + "Z"
    for h in hosts:
        ip = h.get("ip")
        doc = {
            "@timestamp": now,
            "ip": ip,
            "mac": h.get("mac"),
            "hostname": h.get("hostname"),
            "vendor": h.get("vendor"),
            "role": h.get("role"),
            "tags": h.get("tags") or [],
            "source": "harmattan",
        }
        at = attack_by_ip.get(ip) or {}
        if at:
            doc["max_risk"] = at.get("max_risk")
            doc["exposure_count"] = at.get("exposure_count")
            doc["exposures"] = at.get("exposures") or []
        meta = {"index": {"_index": index}}
        lines.append(json.dumps(meta))
        lines.append(json.dumps(doc, default=str))
    return "\n".join(lines) + ("\n" if lines else "")
