"""
HARMATTAN — feature_report: render the new modules' results as HTML report annexes.

Each helper takes the module's dict result and returns a small HTML fragment. These
fragments are passed to report.build_html_report(..., extras=[...]) under "8bis".
"""
from __future__ import annotations

from html import escape as _esc

from core.logging_setup import get_logger

log = get_logger("harmattan.feature_report")


def intel_html(corr: dict | None) -> str:
    corr = corr or {}
    advs = corr.get("adversaries") or []
    if not advs:
        return "<em>Aucune corrélation d'adversaire.</em>"
    rows = []
    for a in advs[:10]:
        rows.append(
            f"<li><b>{_esc(a.get('name',''))}</b> "
            f"— confiance {int(a.get('confidence',0)*100)}% "
            f"· {len(a.get('matched_techniques') or [])} technique(s) "
            f"(<span class='mono'>{', '.join(_esc(t) for t in (a.get('matched_techniques') or [])[:4])}</span>)<br>"
            f"<span style='color:var(--muted)'>{_esc(a.get('note',''))}</span></li>"
        )
    return f"<ul>{''.join(rows)}</ul>"


def iot_html(res: dict | None) -> str:
    res = res or {}
    devs = res.get("devices") or []
    if not devs:
        return "<em>Aucun appareil IoT détecté.</em>"
    risk = _esc(str(res.get("default_cred_risk", "none")))
    rows = []
    for d in devs[:15]:
        fams = ", ".join(_esc(f) for f in (d.get("families") or [])) or "—"
        ports = ", ".join(str(p) for p in (d.get("ports") or [])[:8]) or "—"
        hints = "; ".join(_esc(h) for h in (d.get("hints") or [])[:2])
        rows.append(
            f"<li><b>{_esc(d.get('ip',''))}</b> · {_esc(d.get('vendor') or '?')} "
            f"· role <span class='mono'>{_esc(d.get('role') or '?')}</span> · familles [{fams}]<br>"
            f"<span style='color:var(--muted)'>ports: {ports} · {hints}</span></li>"
        )
    return f"<p>Risque creds par défaut : <b>{risk}</b> · {len(devs)} appareil(s).</p><ul>{''.join(rows)}</ul>"


def dns_html(res: dict | None) -> str:
    res = res or {}
    found = res.get("resolved") or []
    if not found:
        return f"<em>Aucun sous-domaine résolu pour {_esc(res.get('domain','?'))}.</em>"
    rows = []
    for r in found[:15]:
        ips = ", ".join(_esc(i) for i in (r.get("ips") or [])[:3])
        rows.append(f"<li><span class='mono'>{_esc(r.get('name',''))}</span> → {ips}</li>")
    axfr = res.get("zone_transfer") or []
    extra = ""
    if axfr:
        extra = f"<p style='color:#b91c1c'>⚠️ Zone transfer autorisé ({len(axfr)} records) — config DNS à corriger.</p>"
    return f"{extra}<ul>{''.join(rows)}</ul>"


def tls_html(res: dict | None) -> str:
    res = res or {}
    certs = res.get("certificates") or []
    if not certs:
        return "<em>Aucun certificat inspecté.</em>"
    rows = []
    for c in certs[:15]:
        if c.get("ok") is False:
            rows.append(f"<li><span class='mono'>{_esc(c.get('ip',''))}</span> : pas de TLS "
                        f"(<span style='color:var(--muted)'>{_esc(c.get('error',''))}</span>)</li>")
            continue
        exp = "EXPIRÉ" if c.get("expired") else f"{c.get('days_remaining','?')}j"
        sev = "color:#b91c1c" if c.get("expired") else ""
        hints = "; ".join(_esc(h) for h in (c.get("hints") or [])[:2])
        rows.append(
            f"<li><span class='mono'>{_esc(c.get('ip',''))}:{c.get('port','')}</span> "
            f"· <span style='{sev}'>{exp}</span> · {_esc(c.get('subject') or '?')}<br>"
            f"<span style='color:var(--muted)'>{hints}</span></li>"
        )
    return f"<ul>{''.join(rows)}</ul>"


def trends_html(res: dict | None) -> str:
    res = res or {}
    new_ports = res.get("new_ports") or {}
    if not new_ports:
        return "<em>Aucune évolution de ports entre scans.</em>"
    rows = []
    for ip, events in list(new_ports.items())[:10]:
        adds = []
        for ev in events:
            adds.append("+".join(str(p) for p in (ev.get("added") or [])))
        rows.append(f"<li><span class='mono'>{_esc(ip)}</span> : nouveaux ports {', '.join(adds)}</li>")
    return f"<p>{len(new_ports)} hôte(s) ont exposé de nouveaux ports.</p><ul>{''.join(rows)}</ul>"


def netflow_html(res: dict | None) -> str:
    res = res or {}
    return f"<p>Enregistrements NetFlow exportés : <b>{res.get('sent', 0)}</b> · total envoyé {res.get('exported_total', 0)}.</p>"


def honeypot_html(res: dict | None) -> str:
    res = res or {}
    if not (res.get("last_connections")):
        return f"<em>Honeypot {'actif' if res.get('running') else 'inactif'} — aucune connexion enregistrée.</em>"
    rows = []
    for c in (res.get("last_connections") or [])[-10:]:
        rows.append(f"<li><span class='mono'>{_esc(c.get('ip',''))}</span> → port {c.get('port')} · {_esc(c.get('ts',''))}</li>")
    return f"<p>{res.get('connections',0)} connexion(s) enregistrée(s).</p><ul>{''.join(rows)}</ul>"


def assemble(modules_state: dict) -> list[dict]:
    """Build the extras list from a dict of module results keyed by name."""
    build = {
        "intel": ("🧠 IntelGatherer — corrélation adversaires", intel_html),
        "iot": ("🤖 IoT-Enumerator — appareils & creds par défaut", iot_html),
        "dns": ("🌐 DNS-Enum — sous-domaines", dns_html),
        "tls": ("🔒 TLS-Analyzer — certificats", tls_html),
        "trends": ("📈 Port-Trends — évolution", trends_html),
        "netflow": ("📡 NetFlow — export", netflow_html),
        "honeypot": ("🎣 Honeypot-Lite — connexions", honeypot_html),
    }
    out = []
    for key, (title, fn) in build.items():
        res = (modules_state or {}).get(key)
        if not res:
            continue
        try:
            out.append({"title": title, "html": fn(res)})
        except Exception as e:  # noqa: BLE001
            log.debug("feature_report %s: %s", key, e)
    return out
