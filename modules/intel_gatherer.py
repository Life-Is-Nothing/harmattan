"""
HARMATTAN — IntelGatherer: adversary-card correlation from detected ATT&CK techniques.

Takes the techniques produced by mitre_map.map_network() and cross-references a small
built-in knowledge base of adversary groups (APTs, tooling) that are known to use them.
Produces a per-adversary confidence card + a defensive recommendation.

Ethics: informational / defensive only. No live threat-intel calls by default.
"""
from __future__ import annotations

from core.logging_setup import get_logger

log = get_logger("harmattan.intel_gatherer")

# Adversary knowledge base: group -> {name, tags, techniques:[...], note}
# Technique IDs refer to MITRE ATT&CK (as used in modules/mitre_map.py).
ADVERSARY_KB = [
    {
        "id": "apt28",
        "name": "APT28 / Fancy Bear",
        "tags": ["espionage", "government"],
        "techniques": ["T1190", "T1071", "T1071.001", "T1021.001", "T1573"],
        "note": "Groupe parrainé par un État, cible gouvernements & défense. Prioriser la défense périmétrique.",
    },
    {
        "id": "apt29",
        "name": "APT29 / Cozy Bear",
        "tags": ["espionage", "government"],
        "techniques": ["T1071", "T1573", "T1048"],
        "note": "Cibles gouvernementales et diplomatiques. Surveiller les canaux chiffrés exfiltrants.",
    },
    {
        "id": "fin7",
        "name": "FIN7 / Carbanak",
        "tags": ["crime", "financial"],
        "techniques": ["T1021.002", "T1021.003", "T1190", "T1071"],
        "note": "Groupe criminel ciblant le retail et la finance. Vérifier POS et points d'entrée web.",
    },
    {
        "id": "lockbit",
        "name": "LockBit / Ransomware",
        "tags": ["crime", "ransomware"],
        "techniques": ["T1021.002", "T1486", "T1190", "T1071.001"],
        "note": "Ransomware-as-a-Service. Couverture SMB + chiffrement. Isoler 445, sauvegardes hors-ligne.",
    },
    {
        "id": "hive",
        "name": "Hive / Ransomware",
        "tags": ["crime", "ransomware"],
        "techniques": ["T1021.002", "T1486"],
        "note": "Exfiltration avant chiffrement (double extorsion). Surveiller l'exfiltration SMB/HTTPS.",
    },
    {
        "id": "mirai",
        "name": "Mirai / IoT Botnet",
        "tags": ["iot", "botnet", "dirty"],
        "techniques": ["T1200", "T0883", "T1071"],
        "note": "Botnet IoT via default creds. Vérifier tout équipement exposé et changer les identifiants usine.",
    },
    {
        "id": "turla",
        "name": "Turla / Snake",
        "tags": ["espionage", "government"],
        "techniques": ["T1071.004", "T1048", "T1573"],
        "note": "Espionnage avancé, tunnels DNS. Surveiller les requêtes DNS exfiltrantes anormales.",
    },
    {
        "id": "sandworm",
        "name": "Sandworm",
        "tags": ["espionage", "ics", "impact"],
        "techniques": ["T1486", "T1190", "T0883"],
        "note": "Capacités ICS + destructive. Critique si OT/protocoles industriels détectés.",
    },
    {
        "id": "lemonduck",
        "name": "LemonDuck / Coinminer",
        "tags": ["crime", "cryptominer"],
        "techniques": ["T1021.002", "T1190", "T1071.001"],
        "note": "Monominage via SMB et services web exposés. Vérifier consommation CPU anormale.",
    },
    {
        "id": "gafgyt",
        "name": "Gafgyt / BASHLITE",
        "tags": ["iot", "botnet", "dirty"],
        "techniques": ["T1200", "T0883"],
        "note": "Botnet IoT pour DDoS. Changer les creds par défaut sur tout équipement réseau.",
    },
]

# Fallback when no adversary matches strongly.
_GENERIC_ADVERSARY = {
    "id": "unattributed",
    "name": "Acteur non attribué",
    "tags": ["unknown"],
    "techniques": [],
    "note": "Aucun groupe connu ne correspond fortement. Appliquer les bonnes pratiques de durcissement.",
}


def _technique_ids(mapping: dict) -> set:
    """Collect the technique IDs present in a mitre_map output."""
    ids = set()
    for t in (mapping or {}).get("techniques", []):
        tid = t.get("technique_id")
        if tid:
            ids.add(tid)
    return ids


def _score_match(adv: dict, present: set) -> tuple[int, list[str]]:
    """Return (matched_count, matched_techniques) for an adversary against present IDs."""
    adv_techs = set(adv.get("techniques", []))
    matched = sorted(present & adv_techs)
    return len(matched), matched


def correlate(mapping: dict | None = None, hosts: list | None = None) -> dict:
    """
    Build adversary cards from a mitre_map output.

    Args:
        mapping: result of mitre_map.map_network() (or anything with a `.techniques` list).
        hosts: optional list of host dicts to add evidence context.

    Returns a dict:
        {
            "technique_count": int,
            "adversaries": [ {adversary card}, ... ],   # sorted by confidence desc
            "top_groups": [str, ...],
            "generated_at": str,
        }
    """
    mapping = mapping or {}
    present = _technique_ids(mapping)
    if not present:
        return {
            "technique_count": 0,
            "adversaries": [],
            "top_groups": [],
            "note": _GENERIC_ADVERSARY["note"],
        }

    cards = []
    for adv in ADVERSARY_KB:
        matched, matched_techs = _score_match(adv, present)
        if matched == 0:
            continue
        coverage = matched / len(set(adv.get("techniques", []))) if adv.get("techniques") else 0
        confidence = min(1.0, coverage * 0.9 + 0.1 * matched)
        cards.append(
            {
                "id": adv["id"],
                "name": adv["name"],
                "tags": adv["tags"],
                "matched_techniques": matched_techs,
                "matched_count": matched,
                "coverage": round(coverage, 3),
                "confidence": round(confidence, 3),
                "note": adv["note"],
            }
        )

    cards.sort(key=lambda c: (-c["confidence"], -c["matched_count"]))

    return {
        "technique_count": len(present),
        "adversaries": cards,
        "top_groups": [c["name"] for c in cards[:3]],
        "generated_at": None,  # filled by caller with datetime if needed (kept deterministic here)
    }


def summarize(correlation: dict) -> str:
    """Human-readable one-liner summary for push_history / notifications."""
    groups = correlation.get("top_groups") or []
    if not groups:
        return "IntelGatherer: aucun groupe d'adversaire fortement corrélé"
    return "IntelGatherer: corrélation -> " + ", ".join(groups)
