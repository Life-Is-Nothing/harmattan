"""
HARMATTAN — Professional multi-format reports (HTML / PDF / DOCX).
Client-ready deliverables with NACF branding.
"""
from __future__ import annotations

import io
from datetime import datetime
from html import escape
from typing import Any, Optional

from core.config import VERSION

# Brand
ORANGE = "F77F00"
CYAN = "2FD9D0"
DARK = "0A0D12"
PANEL = "151B25"
MUTED = "8B96A8"
RED = "EF4444"
GREEN = "12A150"


def _meta(network, arp, attack, vuln) -> dict:
    network = network or {}
    arp = arp or {}
    attack = attack or {}
    vuln = vuln or {}
    hosts = arp.get("count") or len(arp.get("hosts") or [])
    exposures = attack.get("total_exposures", 0)
    grade = attack.get("grade", "—")
    score = attack.get("risk_score", 0)
    cves = vuln.get("total_findings", 0)
    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ssid": network.get("ssid") or "—",
        "subnet": network.get("subnet") or "—",
        "gateway": network.get("gateway") or "—",
        "local_ip": network.get("local_ip") or "—",
        "hosts": hosts,
        "exposures": exposures,
        "grade": grade,
        "score": score,
        "cves": cves,
        "roles": arp.get("roles") or {},
        "recommendations": attack.get("recommendations") or [],
    }


# ---------------------------------------------------------------------------
# HTML (premium, print-ready)
# ---------------------------------------------------------------------------
def build_html_report(
    network: Optional[dict],
    arp: Optional[dict],
    nmap: Optional[dict],
    vuln: Optional[dict],
    attack: Optional[dict],
    *,
    title: str = "Rapport d'audit réseau",
    client: str = "",
    operator: str = "NACF / HARMATTAN",
) -> str:
    network = network or {}
    arp = arp or {}
    nmap = nmap or {}
    vuln = vuln or {}
    attack = attack or {}
    m = _meta(network, arp, attack, vuln)
    now = m["generated"]
    client_l = escape(client or "Interne")
    operator_l = escape(operator)

    hosts_rows = ""
    for h in arp.get("hosts", []):
        ports = ", ".join(str(p) for p in h.get("open_ports", [])) or "—"
        hosts_rows += f"""
        <tr>
          <td class="mono">{escape(h.get('ip',''))}</td>
          <td class="mono">{escape(h.get('mac') or '—')}</td>
          <td>{escape(h.get('vendor') or '—')}</td>
          <td>{escape(h.get('hostname') or '—')}</td>
          <td><span class="pill">{escape(h.get('role') or '—')}</span></td>
          <td>{escape(h.get('os_hint') or '—')}</td>
          <td class="mono">{escape(ports)}</td>
        </tr>"""

    nmap_sections = ""
    for h in nmap.get("hosts", []):
        port_rows = ""
        for p in h.get("ports", []):
            if p.get("state") != "open":
                continue
            port_rows += f"""
            <tr>
              <td class="mono">{escape(str(p.get('port')))}/{escape(p.get('protocol',''))}</td>
              <td>{escape(p.get('service') or '')}</td>
              <td>{escape((p.get('product') or '') + ' ' + (p.get('version') or ''))}</td>
            </tr>"""
        os_name = h["os_matches"][0]["name"] if h.get("os_matches") else "—"
        nmap_sections += f"""
        <h3>{escape(h.get('ip',''))} — {escape(os_name)}</h3>
        <table>
          <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
          <tbody>{port_rows or '<tr><td colspan="3">Aucun port ouvert</td></tr>'}</tbody>
        </table>"""

    attack_rows = ""
    for h in attack.get("hosts", []):
        for e in h.get("exposures", []):
            attack_rows += f"""
            <tr>
              <td class="mono">{escape(h.get('ip',''))}</td>
              <td>{escape(h.get('role') or '')}</td>
              <td class="mono">{e.get('port')}</td>
              <td>{escape(e.get('service') or '')}</td>
              <td><span class="sev sev-{escape(e.get('risk',''))}">{escape(e.get('risk',''))}</span></td>
              <td>{escape(e.get('recommendation') or '—')}</td>
            </tr>"""

    vuln_rows = ""
    for h in vuln.get("hosts", []):
        for s in h.get("services", []):
            for c in s.get("cves", []):
                vuln_rows += f"""
                <tr>
                  <td class="mono">{escape(h.get('ip',''))}</td>
                  <td>{escape(s.get('product',''))} {escape(s.get('version',''))}</td>
                  <td><a href="{escape(c.get('url',''))}">{escape(c.get('id',''))}</a></td>
                  <td>{c.get('score') if c.get('score') is not None else '—'}</td>
                  <td><span class="sev sev-{escape(c.get('severity',''))}">{escape(c.get('severity',''))}</span></td>
                  <td>{escape((c.get('description') or '')[:220])}</td>
                </tr>"""

    recs = "".join(f"<li>{escape(r)}</li>" for r in m["recommendations"][:20])
    roles_html = "".join(
        f'<div class="kpi"><div class="k">{escape(str(v))}</div><div class="l">{escape(k)}</div></div>'
        for k, v in (m["roles"] or {}).items()
    ) or '<div class="kpi"><div class="k">—</div><div class="l">rôles</div></div>'

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>HARMATTAN — {escape(title)} — {now}</title>
<style>
  @page {{ size: A4; margin: 18mm 16mm; }}
  :root {{
    --orange: #{ORANGE}; --cyan: #{CYAN}; --bg: #0a0d12; --panel: #121820;
    --border: #232b38; --text: #e8ecf1; --muted: #8b96a8; --red: #{RED}; --green: #{GREEN};
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: var(--bg); color: var(--text);
    margin: 0; padding: 0; line-height: 1.5; font-size: 13px;
  }}
  .page {{ max-width: 980px; margin: 0 auto; padding: 32px 28px 64px; }}
  .cover {{
    border: 1px solid var(--border); border-radius: 14px; padding: 40px 36px;
    background: linear-gradient(145deg, #10151d 0%, #0a0d12 60%, #1a1200 100%);
    margin-bottom: 28px; position: relative; overflow: hidden;
  }}
  .cover::after {{
    content: ''; position: absolute; right: -40px; top: -40px;
    width: 180px; height: 180px; border-radius: 50%;
    background: radial-gradient(circle, rgba(247,127,0,.25), transparent 70%);
  }}
  .brand {{ color: var(--orange); font-weight: 800; letter-spacing: .14em; font-size: 12px; text-transform: uppercase; }}
  h1 {{ font-size: 28px; margin: 12px 0 8px; letter-spacing: -.02em; }}
  .subtitle {{ color: var(--muted); font-size: 14px; margin-bottom: 22px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(140px,1fr)); gap: 10px; }}
  .meta-item {{ background: rgba(0,0,0,.25); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }}
  .meta-item .l {{ font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }}
  .meta-item .v {{ font-size: 13px; margin-top: 4px; font-family: ui-monospace, monospace; }}
  .classify {{
    display: inline-block; margin-top: 18px; padding: 6px 12px; border-radius: 6px;
    background: rgba(247,127,0,.12); border: 1px solid rgba(247,127,0,.35); color: var(--orange);
    font-size: 11px; font-weight: 600; letter-spacing: .04em;
  }}
  h2 {{
    color: var(--cyan); font-size: 15px; text-transform: uppercase; letter-spacing: .1em;
    border-bottom: 1px solid var(--border); padding-bottom: 8px; margin: 32px 0 14px;
  }}
  h3 {{ font-size: 14px; color: var(--text); margin: 18px 0 8px; }}
  .exec {{
    display: grid; grid-template-columns: 140px 1fr; gap: 16px; align-items: center;
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 20px;
  }}
  .grade {{ font-size: 64px; font-weight: 800; color: var(--orange); line-height: 1; text-align: center; }}
  .grade small {{ display: block; font-size: 12px; color: var(--muted); font-weight: 500; margin-top: 6px; }}
  .kpis {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(100px,1fr)); gap: 10px; }}
  .kpi {{ background: #0a0d12; border: 1px solid var(--border); border-radius: 8px; padding: 12px; text-align: center; }}
  .kpi .k {{ font-size: 22px; font-weight: 700; color: var(--orange); }}
  .kpi .l {{ font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0 18px; font-size: 12px; }}
  th, td {{ border: 1px solid var(--border); padding: 8px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #151b25; color: var(--muted); text-transform: uppercase; font-size: 10px; letter-spacing: .06em; }}
  tr:nth-child(even) td {{ background: rgba(255,255,255,.015); }}
  .mono {{ font-family: ui-monospace, 'Cascadia Code', monospace; font-size: 11px; }}
  .pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: rgba(47,217,208,.12); color: var(--cyan); font-size: 10px; }}
  .sev {{ font-weight: 700; text-transform: uppercase; font-size: 10px; }}
  .sev-critique, .sev-critical {{ color: var(--red); }}
  .sev-haute, .sev-high {{ color: var(--orange); }}
  .sev-moyenne, .sev-medium {{ color: var(--cyan); }}
  .sev-faible, .sev-low {{ color: var(--muted); }}
  a {{ color: var(--cyan); }}
  .warn {{
    background: rgba(247,127,0,.08); border-left: 3px solid var(--orange);
    padding: 12px 14px; margin: 14px 0; font-size: 12px; color: var(--muted);
  }}
  .footer {{
    margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
    color: var(--muted); font-size: 11px; display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap;
  }}
  ul {{ margin: 8px 0 16px; padding-left: 18px; color: var(--muted); }}
  li {{ margin-bottom: 4px; }}
  @media print {{
    body {{ background: #fff; color: #111; }}
    .cover {{ background: #f7f7f7; color: #111; }}
    h2 {{ color: #0a6; }}
    th {{ background: #eee; color: #444; }}
    .grade {{ color: #c60; }}
    a {{ color: #06c; }}
  }}
</style>
</head>
<body>
<div class="page">
  <section class="cover">
    <div class="brand">◆ HARMATTAN · Network Intelligence</div>
    <h1>{escape(title)}</h1>
    <p class="subtitle">Audit réseau autorisé · Livrable confidentiel</p>
    <div class="meta-grid">
      <div class="meta-item"><div class="l">Client</div><div class="v">{client_l}</div></div>
      <div class="meta-item"><div class="l">Opérateur</div><div class="v">{operator_l}</div></div>
      <div class="meta-item"><div class="l">Date</div><div class="v">{escape(now)}</div></div>
      <div class="meta-item"><div class="l">Outil</div><div class="v">HARMATTAN v{VERSION}</div></div>
      <div class="meta-item"><div class="l">SSID</div><div class="v">{escape(str(m['ssid']))}</div></div>
      <div class="meta-item"><div class="l">Subnet</div><div class="v">{escape(str(m['subnet']))}</div></div>
      <div class="meta-item"><div class="l">Gateway</div><div class="v">{escape(str(m['gateway']))}</div></div>
      <div class="meta-item"><div class="l">IP locale</div><div class="v">{escape(str(m['local_ip']))}</div></div>
    </div>
    <div class="classify">CONFIDENTIEL — Usage réservé au destinataire autorisé</div>
  </section>

  <div class="warn">
    Ce document présente les résultats d'un audit réseau réalisé dans un cadre autorisé.
    Toute redistribution hors des parties concernées est interdite. Les tests non autorisés sont illégaux.
  </div>

  <h2>1. Synthèse exécutive</h2>
  <div class="exec">
    <div class="grade">{escape(str(m['grade']))}<small>Grade · {m['score']}/100</small></div>
    <div class="kpis">
      <div class="kpi"><div class="k">{m['hosts']}</div><div class="l">Appareils</div></div>
      <div class="kpi"><div class="k">{m['exposures']}</div><div class="l">Expositions</div></div>
      <div class="kpi"><div class="k">{m['cves']}</div><div class="l">CVE</div></div>
      <div class="kpi"><div class="k">{escape(str(m['gateway'])[:12])}</div><div class="l">Gateway</div></div>
    </div>
  </div>
  <p style="color:var(--muted);margin-top:12px;">
    L'audit a identifié <b style="color:var(--text)">{m['hosts']}</b> appareil(s) sur le segment
    <b style="color:var(--text)">{escape(str(m['subnet']))}</b>, avec
    <b style="color:var(--text)">{m['exposures']}</b> exposition(s) de surface d'attaque
    et <b style="color:var(--text)">{m['cves']}</b> corrélation(s) CVE.
  </p>

  <h2>2. Répartition des rôles</h2>
  <div class="kpis">{roles_html}</div>

  <h2>3. Recommandations prioritaires</h2>
  {"<ul>" + recs + "</ul>" if recs else "<p style='color:var(--muted)'>Aucune recommandation critique automatique.</p>"}

  <h2>4. Inventaire des hôtes ({m['hosts']})</h2>
  <table>
    <thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>Rôle</th><th>OS</th><th>Ports</th></tr></thead>
    <tbody>{hosts_rows or '<tr><td colspan="7">Aucun hôte découvert</td></tr>'}</tbody>
  </table>

  <h2>5. Surface d'attaque</h2>
  <p style="color:var(--muted)">Expositions: {m['exposures']} · Hôtes analysés: {attack.get('total_hosts', 0)}</p>
  <table>
    <thead><tr><th>IP</th><th>Rôle</th><th>Port</th><th>Service</th><th>Risque</th><th>Remédiation</th></tr></thead>
    <tbody>{attack_rows or '<tr><td colspan="6">Aucune exposition</td></tr>'}</tbody>
  </table>

  <h2>6. Résultats Nmap</h2>
  {nmap_sections or '<p style="color:var(--muted)">Aucun scan nmap enregistré pour cette session.</p>'}

  <h2>7. Vulnérabilités CVE</h2>
  <table>
    <thead><tr><th>IP</th><th>Produit</th><th>CVE</th><th>Score</th><th>Sévérité</th><th>Description</th></tr></thead>
    <tbody>{vuln_rows or '<tr><td colspan="6">Aucune CVE corrélée</td></tr>'}</tbody>
  </table>

  <h2>8. Méthodologie</h2>
  <ul>
    <li>Découverte ARP broadcast + fingerprinting (OUI, TTL, ports, SNMP, hostname)</li>
    <li>Scan de services nmap (profils sélectionnés)</li>
    <li>Agrégation de surface d'attaque et scoring de risque</li>
    <li>Corrélation CVE via NVD (si scan versions disponible)</li>
  </ul>

  <h2>9. Limitations</h2>
  <ul>
    <li>Les hôtes silencieux (pas de réponse ARP) peuvent être absents</li>
    <li>La corrélation CVE dépend de la précision product/version nmap</li>
    <li>Pas de tests d'exploitation destructifs dans ce livrable réseau</li>
  </ul>

  <div class="footer">
    <span>HARMATTAN v{VERSION} · NACF · {escape(now)}</span>
    <span>Document confidentiel — ne pas diffuser</span>
  </div>
</div>
</body>
</html>"""


def build_json_report(
    network: Optional[dict],
    arp: Optional[dict],
    nmap: Optional[dict],
    vuln: Optional[dict],
    attack: Optional[dict],
    **kwargs,
) -> dict:
    return {
        "meta": {
            "generated": datetime.now().isoformat(timespec="seconds"),
            "tool": "HARMATTAN",
            "version": VERSION,
            **{k: v for k, v in kwargs.items() if v},
        },
        "summary": _meta(network, arp, attack, vuln),
        "network": network,
        "arp": arp,
        "nmap": nmap,
        "vuln": vuln,
        "attack": attack,
    }


# ---------------------------------------------------------------------------
# PDF (reportlab)
# ---------------------------------------------------------------------------
def build_pdf_report(
    network: Optional[dict],
    arp: Optional[dict],
    nmap: Optional[dict],
    vuln: Optional[dict],
    attack: Optional[dict],
    *,
    title: str = "Rapport d'audit réseau",
    client: str = "",
    operator: str = "NACF / HARMATTAN",
) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
        KeepTogether,
        HRFlowable,
    )

    network = network or {}
    arp = arp or {}
    nmap = nmap or {}
    vuln = vuln or {}
    attack = attack or {}
    m = _meta(network, arp, attack, vuln)
    buf = io.BytesIO()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"HARMATTAN — {title}",
        author=operator,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverTitle", fontSize=22, leading=26, textColor=colors.HexColor("#1a1a1a"), spaceAfter=8, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="H2", fontSize=12, leading=15, textColor=colors.HexColor("#0d7377"), spaceBefore=14, spaceAfter=8, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Body", fontSize=9, leading=12, textColor=colors.HexColor("#222"), alignment=TA_JUSTIFY))
    styles.add(ParagraphStyle(name="Muted", fontSize=8, leading=10, textColor=colors.HexColor("#666")))
    styles.add(ParagraphStyle(name="Brand", fontSize=9, textColor=colors.HexColor("#c45c00"), fontName="Helvetica-Bold", letterSpacing=1))
    styles.add(ParagraphStyle(name="GradeBig", fontSize=36, leading=40, alignment=TA_CENTER, textColor=colors.HexColor("#c45c00"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Cell", fontSize=7.5, leading=9, textColor=colors.HexColor("#222")))
    styles.add(ParagraphStyle(name="CellHead", fontSize=7.5, leading=9, textColor=colors.HexColor("#444"), fontName="Helvetica-Bold"))

    story = []
    story.append(Paragraph("◆ HARMATTAN · NETWORK INTELLIGENCE", styles["Brand"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(escape(title), styles["CoverTitle"]))
    story.append(Paragraph(
        f"<b>Client:</b> {escape(client or 'Interne')} &nbsp;|&nbsp; "
        f"<b>Opérateur:</b> {escape(operator)} &nbsp;|&nbsp; "
        f"<b>Date:</b> {escape(m['generated'])} &nbsp;|&nbsp; "
        f"<b>Version:</b> {VERSION}",
        styles["Muted"],
    ))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#f77f00"), spaceAfter=10))
    story.append(Paragraph(
        "<b>CONFIDENTIEL</b> — Document réservé aux parties autorisées. "
        "Audit réalisé dans un cadre légal explicite.",
        styles["Muted"],
    ))
    story.append(Spacer(1, 10))

    # Context table
    ctx = [
        [Paragraph("<b>SSID</b>", styles["CellHead"]), Paragraph(escape(str(m["ssid"])), styles["Cell"]),
         Paragraph("<b>Subnet</b>", styles["CellHead"]), Paragraph(escape(str(m["subnet"])), styles["Cell"])],
        [Paragraph("<b>Gateway</b>", styles["CellHead"]), Paragraph(escape(str(m["gateway"])), styles["Cell"]),
         Paragraph("<b>IP locale</b>", styles["CellHead"]), Paragraph(escape(str(m["local_ip"])), styles["Cell"])],
    ]
    t = Table(ctx, colWidths=[28 * mm, 55 * mm, 28 * mm, 55 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f5f5f5")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # Exec
    story.append(Paragraph("1. Synthèse exécutive", styles["H2"]))
    kpi = [
        [Paragraph(f"<font size='28' color='#c45c00'><b>{escape(str(m['grade']))}</b></font><br/><font size='8'>Grade · {m['score']}/100</font>", styles["Cell"]),
         Paragraph(f"<b>{m['hosts']}</b><br/>Appareils", styles["Cell"]),
         Paragraph(f"<b>{m['exposures']}</b><br/>Expositions", styles["Cell"]),
         Paragraph(f"<b>{m['cves']}</b><br/>CVE", styles["Cell"])],
    ]
    kt = Table(kpi, colWidths=[40 * mm, 40 * mm, 40 * mm, 40 * mm])
    kt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff8f0")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#f77f00")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(kt)
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"L'audit a identifié <b>{m['hosts']}</b> appareil(s) sur <b>{escape(str(m['subnet']))}</b>, "
        f"avec <b>{m['exposures']}</b> exposition(s) et <b>{m['cves']}</b> corrélation(s) CVE. "
        f"Grade global de risque : <b>{escape(str(m['grade']))}</b> ({m['score']}/100).",
        styles["Body"],
    ))

    if m["recommendations"]:
        story.append(Paragraph("2. Recommandations prioritaires", styles["H2"]))
        for r in m["recommendations"][:15]:
            story.append(Paragraph(f"• {escape(r)}", styles["Body"]))

    # Hosts
    story.append(Paragraph("3. Inventaire des hôtes", styles["H2"]))
    header = [Paragraph(x, styles["CellHead"]) for x in ["IP", "MAC", "Vendor", "Hostname", "Rôle", "Ports"]]
    rows = [header]
    for h in (arp.get("hosts") or [])[:80]:
        ports = ", ".join(str(p) for p in h.get("open_ports", [])[:8]) or "—"
        rows.append([
            Paragraph(escape(h.get("ip") or ""), styles["Cell"]),
            Paragraph(escape(h.get("mac") or "—"), styles["Cell"]),
            Paragraph(escape((h.get("vendor") or "—")[:24]), styles["Cell"]),
            Paragraph(escape((h.get("hostname") or "—")[:20]), styles["Cell"]),
            Paragraph(escape(h.get("role") or "—"), styles["Cell"]),
            Paragraph(escape(ports[:40]), styles["Cell"]),
        ])
    if len(rows) == 1:
        rows.append([Paragraph("Aucun hôte", styles["Cell"])] + [Paragraph("", styles["Cell"])] * 5)
    ht = Table(rows, colWidths=[28 * mm, 32 * mm, 32 * mm, 28 * mm, 22 * mm, 30 * mm])
    ht.setStyle(_table_style())
    story.append(ht)

    # Attack surface
    story.append(Paragraph("4. Surface d'attaque", styles["H2"]))
    ah = [Paragraph(x, styles["CellHead"]) for x in ["IP", "Port", "Service", "Risque", "Reco"]]
    arows = [ah]
    for h in attack.get("hosts") or []:
        for e in h.get("exposures") or []:
            arows.append([
                Paragraph(escape(h.get("ip") or ""), styles["Cell"]),
                Paragraph(str(e.get("port") or ""), styles["Cell"]),
                Paragraph(escape((e.get("service") or "")[:18]), styles["Cell"]),
                Paragraph(escape(e.get("risk") or ""), styles["Cell"]),
                Paragraph(escape((e.get("recommendation") or "—")[:50]), styles["Cell"]),
            ])
            if len(arows) > 60:
                break
        if len(arows) > 60:
            break
    if len(arows) == 1:
        arows.append([Paragraph("Aucune exposition", styles["Cell"])] + [Paragraph("", styles["Cell"])] * 4)
    at = Table(arows, colWidths=[28 * mm, 16 * mm, 28 * mm, 22 * mm, 72 * mm])
    at.setStyle(_table_style())
    story.append(at)

    # Nmap brief
    story.append(Paragraph("5. Scans Nmap (extrait)", styles["H2"]))
    nh = [Paragraph(x, styles["CellHead"]) for x in ["IP", "Port", "Service", "Produit / Version"]]
    nrows = [nh]
    for h in nmap.get("hosts") or []:
        for p in h.get("ports") or []:
            if p.get("state") != "open":
                continue
            nrows.append([
                Paragraph(escape(h.get("ip") or ""), styles["Cell"]),
                Paragraph(f"{p.get('port')}/{p.get('protocol')}", styles["Cell"]),
                Paragraph(escape(p.get("service") or ""), styles["Cell"]),
                Paragraph(escape(f"{p.get('product') or ''} {p.get('version') or ''}".strip()[:40]), styles["Cell"]),
            ])
            if len(nrows) > 50:
                break
        if len(nrows) > 50:
            break
    if len(nrows) == 1:
        nrows.append([Paragraph("Aucun résultat nmap", styles["Cell"])] + [Paragraph("", styles["Cell"])] * 3)
    nt = Table(nrows, colWidths=[30 * mm, 22 * mm, 30 * mm, 84 * mm])
    nt.setStyle(_table_style())
    story.append(nt)

    # CVE
    story.append(Paragraph("6. Vulnérabilités CVE (extrait)", styles["H2"]))
    vh = [Paragraph(x, styles["CellHead"]) for x in ["IP", "Produit", "CVE", "Score", "Sev"]]
    vrows = [vh]
    for h in vuln.get("hosts") or []:
        for s in h.get("services") or []:
            for c in s.get("cves") or []:
                vrows.append([
                    Paragraph(escape(h.get("ip") or ""), styles["Cell"]),
                    Paragraph(escape(f"{s.get('product','')} {s.get('version','')}"[:28]), styles["Cell"]),
                    Paragraph(escape(c.get("id") or ""), styles["Cell"]),
                    Paragraph(str(c.get("score") if c.get("score") is not None else "—"), styles["Cell"]),
                    Paragraph(escape(c.get("severity") or ""), styles["Cell"]),
                ])
                if len(vrows) > 40:
                    break
            if len(vrows) > 40:
                break
        if len(vrows) > 40:
            break
    if len(vrows) == 1:
        vrows.append([Paragraph("Aucune CVE", styles["Cell"])] + [Paragraph("", styles["Cell"])] * 4)
    vt = Table(vrows, colWidths=[28 * mm, 50 * mm, 35 * mm, 18 * mm, 25 * mm])
    vt.setStyle(_table_style())
    story.append(vt)

    story.append(Paragraph("7. Méthodologie & limitations", styles["H2"]))
    story.append(Paragraph(
        "Découverte ARP + fingerprinting, scans nmap, scoring de surface d'attaque, "
        "corrélation NVD. Les hôtes silencieux peuvent être absents. Les CVE dépendent "
        "de la précision product/version. Aucune exploitation destructive n'est incluse.",
        styles["Body"],
    ))
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc"), spaceAfter=6))
    story.append(Paragraph(
        f"HARMATTAN v{VERSION} · NACF · {escape(m['generated'])} · Document confidentiel",
        styles["Muted"],
    ))

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#888888"))
        canvas.drawString(16 * mm, 10 * mm, "HARMATTAN — Confidentiel")
        canvas.drawRightString(A4[0] - 16 * mm, 10 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def _table_style():
    from reportlab.lib import colors
    from reportlab.platypus import TableStyle
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
        ("INNERGRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
    ])


# ---------------------------------------------------------------------------
# DOCX
# ---------------------------------------------------------------------------
def build_docx_report(
    network: Optional[dict],
    arp: Optional[dict],
    nmap: Optional[dict],
    vuln: Optional[dict],
    attack: Optional[dict],
    *,
    title: str = "Rapport d'audit réseau",
    client: str = "",
    operator: str = "NACF / HARMATTAN",
) -> bytes:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
    from docx.shared import Cm, Pt, RGBColor

    network = network or {}
    arp = arp or {}
    nmap = nmap or {}
    vuln = vuln or {}
    attack = attack or {}
    m = _meta(network, arp, attack, vuln)

    doc = Document()
    for section in doc.sections:
        section.top_margin = Cm(1.6)
        section.bottom_margin = Cm(1.6)
        section.left_margin = Cm(1.8)
        section.right_margin = Cm(1.8)

    brand = doc.add_paragraph()
    run = brand.add_run("◆ HARMATTAN · NETWORK INTELLIGENCE")
    run.bold = True
    run.font.size = Pt(10)
    run.font.color.rgb = RGBColor(0xC4, 0x5C, 0x00)

    h = doc.add_heading(title, level=0)
    h.runs[0].font.color.rgb = RGBColor(0x1A, 0x1A, 0x1A)

    p = doc.add_paragraph()
    p.add_run(f"Client: {client or 'Interne'}  |  Opérateur: {operator}  |  Date: {m['generated']}  |  v{VERSION}").font.size = Pt(9)

    conf = doc.add_paragraph()
    r = conf.add_run("CONFIDENTIEL — Usage réservé au destinataire autorisé.")
    r.bold = True
    r.font.size = Pt(9)
    r.font.color.rgb = RGBColor(0xC4, 0x5C, 0x00)

    doc.add_heading("1. Synthèse exécutive", level=1)
    doc.add_paragraph(
        f"Grade: {m['grade']} ({m['score']}/100) — "
        f"{m['hosts']} appareil(s), {m['exposures']} exposition(s), {m['cves']} CVE. "
        f"Segment {m['subnet']} · Gateway {m['gateway']} · SSID {m['ssid']}."
    )

    if m["recommendations"]:
        doc.add_heading("2. Recommandations prioritaires", level=1)
        for rec in m["recommendations"][:15]:
            doc.add_paragraph(rec, style="List Bullet")

    doc.add_heading("3. Inventaire des hôtes", level=1)
    table = doc.add_table(rows=1, cols=6)
    table.style = "Table Grid"
    hdr = table.rows[0].cells
    for i, name in enumerate(["IP", "MAC", "Vendor", "Hostname", "Rôle", "Ports"]):
        hdr[i].text = name
        _shade_cell(hdr[i], "EEEEEE")
    for h in (arp.get("hosts") or [])[:100]:
        row = table.add_row().cells
        row[0].text = h.get("ip") or ""
        row[1].text = h.get("mac") or ""
        row[2].text = (h.get("vendor") or "")[:40]
        row[3].text = h.get("hostname") or ""
        row[4].text = h.get("role") or ""
        row[5].text = ", ".join(str(p) for p in h.get("open_ports", [])[:10])

    doc.add_heading("4. Surface d'attaque", level=1)
    at = doc.add_table(rows=1, cols=5)
    at.style = "Table Grid"
    for i, name in enumerate(["IP", "Port", "Service", "Risque", "Remédiation"]):
        at.rows[0].cells[i].text = name
        _shade_cell(at.rows[0].cells[i], "EEEEEE")
    n = 0
    for h in attack.get("hosts") or []:
        for e in h.get("exposures") or []:
            row = at.add_row().cells
            row[0].text = h.get("ip") or ""
            row[1].text = str(e.get("port") or "")
            row[2].text = e.get("service") or ""
            row[3].text = e.get("risk") or ""
            row[4].text = (e.get("recommendation") or "")[:120]
            n += 1
            if n >= 80:
                break
        if n >= 80:
            break

    doc.add_heading("5. CVE", level=1)
    vt = doc.add_table(rows=1, cols=5)
    vt.style = "Table Grid"
    for i, name in enumerate(["IP", "Produit", "CVE", "Score", "Sévérité"]):
        vt.rows[0].cells[i].text = name
        _shade_cell(vt.rows[0].cells[i], "EEEEEE")
    n = 0
    for h in vuln.get("hosts") or []:
        for s in h.get("services") or []:
            for c in s.get("cves") or []:
                row = vt.add_row().cells
                row[0].text = h.get("ip") or ""
                row[1].text = f"{s.get('product','')} {s.get('version','')}"[:40]
                row[2].text = c.get("id") or ""
                row[3].text = str(c.get("score") if c.get("score") is not None else "—")
                row[4].text = c.get("severity") or ""
                n += 1
                if n >= 50:
                    break
            if n >= 50:
                break
        if n >= 50:
            break

    doc.add_heading("6. Méthodologie", level=1)
    doc.add_paragraph(
        "ARP discovery + fingerprinting, nmap, attack surface scoring, corrélation NVD. "
        "Livrable non destructif. Usage strictement autorisé."
    )
    foot = doc.add_paragraph()
    fr = foot.add_run(f"HARMATTAN v{VERSION} · NACF · {m['generated']} · Confidentiel")
    fr.font.size = Pt(8)
    fr.font.color.rgb = RGBColor(0x88, 0x88, 0x88)

    bio = io.BytesIO()
    doc.save(bio)
    return bio.getvalue()


def _shade_cell(cell, hex_color: str) -> None:
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), hex_color)
    shd.set(qn("w:val"), "clear")
    tc_pr.append(shd)
