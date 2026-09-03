"""
HARMATTAN — IoT-Enumerator: identify IoT / embedded devices and flag default-credential risk.

Leverages modules/default_creds.py (banner & vendor heuristics) plus
modules/fingerprinting.py role inference to enumerate IoT-ish hosts on an authorized
network and produce a per-device firmware/risk card.

Defensive / informational only. Never attempts active login against third-party devices.
"""
from __future__ import annotations

from core.logging_setup import get_logger

log = get_logger("harmattan.iot_enumerator")

# IoT-ish roles recognized by fingerprinting.infer_role()
_IOT_ROLES = {"iot", "camera", "printer", "router", "ap", "nas", "ipmi", "voip"}

# Known device families → likely firmware/CVE notes (educational, best-effort).
IOT_FAMILY_HINTS = [
    {
        "family": "hikvision",
        "pattern": ["hikvision", "hik", "iVMS"],
        "hints": ["CVE liées caméras Hikvision à vérifier selon version firmware."],
    },
    {
        "family": "dahua",
        "pattern": ["dahua", "dvr", "xvr"],
        "hints": ["CVE DVR Dahua historiques (auth bypass, RCE). Mettre à jour le firmware."],
    },
    {
        "family": "tp-link",
        "pattern": ["tp-link", "tplink"],
        "hints": ["CVE routeurs TP-Link selon modèle. Vérifier le firmware."],
    },
    {
        "family": "netgear",
        "pattern": ["netgear"],
        "hints": ["CVE Netgear (path traversal, RCE) selon modèle. Mettre à jour."],
    },
    {
        "family": "axis",
        "pattern": ["axis"],
        "hints": ["Caméras Axis : changer les creds par défaut, à jour firmware."],
    },
    {
        "family": "trendnet",
        "pattern": ["trendnet", "trend net"],
        "hints": ["CVE caméras TRENDnet. Vérifier l'exposition et les creds."],
    },
    {
        "family": "synology",
        "pattern": ["synology"],
        "hints": ["NAS Synology : patchs réguliers, désactiver l'accès public inutile."],
    },
    {
        "family": "qnap",
        "pattern": ["qnap"],
        "hints": ["NAS QNAP : CVE RCE historiques. Mettre à jour immédiatement."],
    },
    {
        "family": "honeywell",
        "pattern": ["honeywell"],
        "hints": ["Équipement Honeywell : vérifier exposure et firmware."],
    },
]


def _family_for(banner: str, vendor: str) -> list[str]:
    haystack = f"{banner} {vendor}".lower()
    fams = []
    for f in IOT_FAMILY_HINTS:
        if any(p in haystack for p in f["pattern"]):
            fams.append(f["family"])
    return fams


def enumerate_hosts(hosts: list[dict], max_hosts: int = 60) -> dict:
    """
    Given a list of (already enriched) host dicts, produce IoT cards.

    Expected host fields: ip, mac, vendor, role, hostname, ports (list of dict with
    `port` + optional `service`/`banner`), and optional `snmp_sysdescr`.

    Returns:
        {
            "total": int,
            "iot_count": int,
            "devices": [ {device card}, ... ],
            "default_cred_risk": "high|medium|low|none",
            "generated_at": None,
        }
    """
    hosts = hosts or []
    devices = []
    risk_levels = []

    for h in hosts[:max_hosts]:
        role = (h.get("role") or "").lower()
        banner_parts = [h.get("snmp_sysdescr") or "", h.get("hostname") or "", h.get("vendor") or ""]
        for p in h.get("ports") or []:
            if p.get("service"):
                banner_parts.append(str(p.get("service")))
            if p.get("banner"):
                banner_parts.append(str(p.get("banner")))
        banner = " ".join(x for x in banner_parts if x)

        is_iot = role in _IOT_ROLES or h.get("vendor") or h.get("ports")
        if not is_iot:
            continue

        families = _family_for(banner, h.get("vendor") or "")
        # default-credential risk via the shared module
        cred_hits = []
        try:
            from modules import default_creds
            cred_hits = default_creds.assess_host(h, deep=False) or []
        except Exception as e:  # noqa: BLE001
            log.debug("iot default_creds assess error: %s", e)
            cred_hits = []

        if cred_hits:
            risk_levels.append("high" if any(
                (c.get("risk") or "moyenne") in ("haute", "high") for c in cred_hits
            ) else "medium")
        else:
            risk_levels.append("low")

        hints = []
        for fam in families:
            for f in IOT_FAMILY_HINTS:
                if f["family"] == fam:
                    hints.extend(f["hints"])
        hints = hints[:6]

        devices.append(
            {
                "ip": h.get("ip"),
                "mac": h.get("mac"),
                "vendor": h.get("vendor") or "?",
                "role": role or "?",
                "hostname": h.get("hostname") or "",
                "ports": [p.get("port") for p in h.get("ports") or [] if p.get("port")],
                "families": families,
                "default_cred_risk": cred_hits or None,
                "hints": hints,
            }
        )

    if "high" in risk_levels:
        overall = "high"
    elif "medium" in risk_levels:
        overall = "medium"
    elif devices:
        overall = "low"
    else:
        overall = "none"

    return {
        "total": len(hosts),
        "iot_count": len(devices),
        "devices": devices,
        "default_cred_risk": overall,
        "generated_at": None,
    }


def summarize(result: dict) -> str:
    count = result.get("iot_count", 0)
    risk = result.get("default_cred_risk", "none")
    return f"IoT-Enumerator: {count} appareil(s) IoT, risque creds par défaut={risk}"
