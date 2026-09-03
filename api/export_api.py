from __future__ import annotations

import csv
import io
import json
import os
import queue
import tempfile
from datetime import datetime

from flask import Blueprint, Response, jsonify, render_template, request

from api.deps import db, job_manager, log, state, api_response, get_runtime_token, require_token, REPORTS_DIR, VERSION
from core.alerts import notify as alert_notify
from core.validation import (
    ValidationError,
    validate_bpf_filter,
    validate_cidr,
    validate_count,
    validate_iface,
    validate_port,
    validate_target,
)
from modules import attack_surface, network_info, report, topology


bp = Blueprint("export", __name__)

@bp.route("/api/export/sahel/push", methods=["POST"])
def api_export_sahel_push():
    """POST hosts JSON vers SAHEL SHIELD (best-effort)."""
    import urllib.request

    data = request.get_json(force=True, silent=True) or {}
    url = (
        data.get("url")
        or db.get_setting("sahel_url")
        or os.environ.get("SAHEL_URL")
        or "http://127.0.0.1:8099"
    ).rstrip("/")
    if data.get("url"):
        db.set_setting("sahel_url", url)
    arp = state.get("last_arp") or {}
    nmap = state.get("last_nmap") or {}
    packets = []
    cap = state.capture
    if cap:
        try:
            packets = cap.packet_index_for_correlation(limit=1500)
        except Exception:
            packets = []
    payload = {
        "format": "harmattan-to-sahel",
        "version": VERSION,
        "exported_at": datetime.now().isoformat(timespec="seconds"),
        "hosts": arp.get("hosts") or [],
        "nmap_hosts": nmap.get("hosts") or [],
        "packets": packets,
        "source": "harmattan-push",
        "subnet": (arp.get("meta") or {}).get("subnet") or network_info.get_local_subnet(),
        "gateway": network_info.get_default_gateway(),
    }
    for path in ("/api/import/harmattan", "/api/correlate/harmattan", "/api/events", "/api/ingest"):
        try:
            body = json.dumps(payload).encode()
            req = urllib.request.Request(
                url + path,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if 200 <= resp.status < 300:
                    return api_response(
                        message=f"Poussé vers Sahel {path}",
                        data={"url": url + path, "hosts": len(payload["hosts"])},
                    )
        except Exception:
            continue
    out = REPORTS_DIR / f"sahel_push_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return api_response(
        message="Sahel non joignable — export local créé",
        data={
            "file": out.name,
            "hosts": len(payload["hosts"]),
            "hint": "Importez ce JSON dans Sahel ou lancez Sahel sur le port 8099",
        },
        status=200,
    )


@bp.route("/api/monitor/status")
def api_monitor_status():
    from modules import monitor as mon

    return jsonify(mon.status())


@bp.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    from modules import monitor as mon

    data = request.get_json(force=True, silent=True) or {}
    ok, msg = mon.start(interval=int(data.get("interval") or 60))
    return api_response(message=msg, status=200 if ok else 400)


@bp.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    from modules import monitor as mon

    ok, msg = mon.stop()
    return api_response(message=msg, status=200 if ok else 400)


@bp.route("/api/scheduler/status")
def api_scheduler_status():
    from modules import scheduler as sched

    return jsonify(sched.status())


@bp.route("/api/scheduler/start", methods=["POST"])
def api_scheduler_start():
    """Scan ARP planifié + rapport HTML optionnel."""
    from modules import scheduler as sched
    from modules import arp_scanner, report as report_mod

    data = request.get_json(force=True, silent=True) or {}
    interval = int(data.get("interval") or 300)
    with_report = bool(data.get("with_report"))

    def scan_fn():
        subnet = network_info.get_local_subnet()
        res = arp_scanner.arp_scan(subnet, enrich=True, light=True)
        hosts = db.apply_overrides_to_hosts(res.get("hosts") or [])
        res = dict(res)
        res["hosts"] = hosts
        res["count"] = len(hosts)
        state.set("last_arp", res)
        db.save_scan("arp", res)
        db.push_history("sched", f"ARP planifié: {len(hosts)} hôtes")
        return res

    def report_fn(result):
        try:
            network = state.get("last_network") or network_info.snapshot()
            html = report_mod.build_html_report(
                network,
                result,
                state.get("last_nmap") or {},
                state.get("last_vuln") or {},
                state.get("last_attack") or {},
            )
            path = REPORTS_DIR / f"scheduled_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            path.write_text(html, encoding="utf-8")
            return path
        except Exception as e:
            log.warning("report_fn: %s", e)
            return None

    ok, msg = sched.start(scan_fn, interval=interval, with_report=with_report, report_fn=report_fn if with_report else None)
    return api_response(message=msg, status=200 if ok else 400, data=sched.status())


@bp.route("/api/scheduler/stop", methods=["POST"])
def api_scheduler_stop():
    from modules import scheduler as sched

    ok, msg = sched.stop()
    return api_response(message=msg, status=200 if ok else 400, data=sched.status())


@bp.route("/api/export/sahel")
def api_export_sahel():
    """Export hosts + meta for SAHEL SHIELD ingestion."""
    arp = state.get("last_arp") or {}
    nmap = state.get("last_nmap") or {}
    payload = {
        "format": "harmattan-to-sahel",
        "version": VERSION,
        "exported_at": datetime.now().isoformat(timespec="seconds"),
        "hosts": arp.get("hosts") or [],
        "nmap_hosts": nmap.get("hosts") or [],
        "subnet": (arp.get("meta") or {}).get("subnet") or network_info.get_local_subnet(),
        "gateway": network_info.get_default_gateway(),
    }
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=harmattan_export_sahel.json"},
    )


@bp.route("/api/export/pt-scope")
def api_export_pt_scope():
    """Export target list for HARMATTAN-PT scope."""
    arp = state.get("last_arp") or {}
    hosts = arp.get("hosts") or []
    lines = []
    for h in hosts:
        ip = h.get("ip")
        if not ip:
            continue
        role = h.get("role") or "host"
        hostn = h.get("hostname") or ""
        lines.append(f"{ip}\t{role}\t{hostn}\t{h.get('vendor') or ''}")
    body = "\n".join(lines) + ("\n" if lines else "")
    return Response(
        body,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=harmattan_pt_scope.txt"},
    )


@bp.route("/api/topology/export.csv")
def api_topology_export_csv():
    arp_hosts = (state.get("last_arp") or {}).get("hosts", [])
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["ip", "mac", "vendor", "hostname", "role", "os_hint", "open_ports"],
    )
    writer.writeheader()
    for h in arp_hosts:
        writer.writerow({
            "ip": h.get("ip"),
            "mac": h.get("mac"),
            "vendor": h.get("vendor"),
            "hostname": h.get("hostname"),
            "role": h.get("role"),
            "os_hint": h.get("os_hint"),
            "open_ports": ";".join(str(p) for p in h.get("open_ports", [])),
        })
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=harmattan_topology.csv"},
    )
def _report_bundle():
    """Collect latest session data for report builders."""
    network = state.get("last_network") or network_info.snapshot()
    arp = state.get("last_arp")
    nmap = state.get("last_nmap")
    vuln = state.get("last_vuln")
    attack = state.get("last_attack") or attack_surface.build_attack_surface(
        (arp or {}).get("hosts", []),
        (nmap or {}).get("hosts", []),
    )
    return network, arp, nmap, vuln, attack


def _report_meta_from_request():
    return {
        "title": request.args.get("title") or "Rapport d'audit réseau",
        "client": request.args.get("client") or "",
        "operator": request.args.get("operator") or "NACF / HARMATTAN",
    }


@bp.route("/api/report.html")
def api_report_html():
    network, arp, nmap, vuln, attack = _report_bundle()
    meta = _report_meta_from_request()
    html = report.build_html_report(network, arp, nmap, vuln, attack, **meta)
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": "attachment; filename=harmattan_report.html"},
    )


@bp.route("/api/report.json")
def api_report_json():
    network, arp, nmap, vuln, attack = _report_bundle()
    meta = _report_meta_from_request()
    payload = report.build_json_report(network, arp, nmap, vuln, attack, **meta)
    return Response(
        json.dumps(payload, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=harmattan_report.json"},
    )


@bp.route("/api/report.pdf")
def api_report_pdf():
    network, arp, nmap, vuln, attack = _report_bundle()
    meta = _report_meta_from_request()
    pdf = report.build_pdf_report(network, arp, nmap, vuln, attack, **meta)
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=harmattan_report.pdf"},
    )


@bp.route("/api/report.docx")
def api_report_docx():
    network, arp, nmap, vuln, attack = _report_bundle()
    meta = _report_meta_from_request()
    docx_bytes = report.build_docx_report(network, arp, nmap, vuln, attack, **meta)
    return Response(
        docx_bytes,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": "attachment; filename=harmattan_report.docx"},
    )
@bp.route("/api/export/stix")
def api_export_stix():
    from modules.export_stix import build_bundle
    from modules.mitre_map import map_network

    arp = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    nmap = (state.get("last_nmap") or {}).get("hosts", [])
    mitre = state.get("last_mitre") or map_network(arp, nmap, state.get("last_attack") or {})
    bundle = build_bundle(arp, nmap, mitre, version=VERSION)
    return Response(
        json.dumps(bundle, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=harmattan_stix_bundle.json"},
    )


@bp.route("/api/export/graphml")
def api_export_graphml():
    from modules.export_graphml import build_graphml

    arp = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    nmap = (state.get("last_nmap") or {}).get("hosts", [])
    graph = topology.build_graph(arp, nmap)
    body = build_graphml(graph.get("nodes") or [], graph.get("edges") or [])
    return Response(
        body,
        mimetype="application/graphml+xml",
        headers={"Content-Disposition": "attachment; filename=harmattan_topology.graphml"},
    )


@bp.route("/api/export/gexf")
def api_export_gexf():
    from modules.export_graphml import build_gexf

    arp = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    nmap = (state.get("last_nmap") or {}).get("hosts", [])
    graph = topology.build_graph(arp, nmap)
    body = build_gexf(graph.get("nodes") or [], graph.get("edges") or [], title=f"HARMATTAN {VERSION}")
    return Response(
        body,
        mimetype="application/gexf+xml",
        headers={"Content-Disposition": "attachment; filename=harmattan_topology.gexf"},
    )


@bp.route("/api/sahel/bridge/status")
def api_sahel_bridge_status():
    from modules import sahel_bridge

    return jsonify(sahel_bridge.status())


@bp.route("/api/sahel/bridge/start", methods=["POST"])
def api_sahel_bridge_start():
    from modules import sahel_bridge

    data = request.get_json(force=True, silent=True) or {}
    url = (
        data.get("url")
        or db.get_setting("sahel_url")
        or os.environ.get("SAHEL_URL")
        or "http://127.0.0.1:8099"
    ).rstrip("/")
    db.set_setting("sahel_url", url)
    interval = int(data.get("interval") or 120)

    def builder():
        arp = state.get("last_arp") or {}
        nmap = state.get("last_nmap") or {}
        return {
            "format": "harmattan-to-sahel",
            "version": VERSION,
            "exported_at": datetime.now().isoformat(timespec="seconds"),
            "source": "harmattan-bridge-live",
            "hosts": arp.get("hosts") or [],
            "nmap_hosts": nmap.get("hosts") or [],
            "scores": (state.get("last_scores") or {}).get("anomalies") or [],
            "mitre": (state.get("last_mitre") or {}).get("techniques") or [],
        }

    ok, msg = sahel_bridge.start(url, interval, builder)
    db.push_history("sahel", msg)
    return api_response(message=msg, status=200 if ok else 400, data=sahel_bridge.status())


@bp.route("/api/sahel/bridge/stop", methods=["POST"])
def api_sahel_bridge_stop():
    from modules import sahel_bridge

    ok, msg = sahel_bridge.stop()
    return api_response(message=msg, status=200 if ok else 400, data=sahel_bridge.status())


# ── New export formats: CSV, XLSX, Markdown ───────────────────


@bp.route("/api/export/csv")
@bp.route("/api/v1/export/csv")
def api_export_csv():
    from core.export_csv import build_csv_report

    arp = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    nmap = (state.get("last_nmap") or {}).get("hosts", [])
    attack = state.get("last_attack") or {}
    vuln = state.get("last_vuln") or {}
    data = {"hosts": arp, "attack_surface": attack, "vuln": vuln, "arp": {"hosts": arp}}
    csv_text = build_csv_report(data)
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=harmattan_report.csv"},
    )


@bp.route("/api/export/xlsx")
@bp.route("/api/v1/export/xlsx")
def api_export_xlsx():
    from core.export_csv import build_xlsx_report

    arp = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    nmap = (state.get("last_nmap") or {}).get("hosts", [])
    attack = state.get("last_attack") or {}
    vuln = state.get("last_vuln") or {}
    data = {"hosts": arp, "attack_surface": attack, "vuln": vuln, "arp": {"hosts": arp}}

    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False)
    try:
        build_xlsx_report(data, tmp.name)
        with open(tmp.name, "rb") as f:
            xlsx_bytes = f.read()
        return Response(
            xlsx_bytes,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=harmattan_report.xlsx"},
        )
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


@bp.route("/api/export/markdown")
@bp.route("/api/v1/export/markdown")
def api_export_markdown():
    from core.export_csv import build_markdown_report

    arp = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    nmap = (state.get("last_nmap") or {}).get("hosts", [])
    attack = state.get("last_attack") or {}
    vuln = state.get("last_vuln") or {}
    data = {"hosts": arp, "attack_surface": attack, "vuln": vuln, "arp": {"hosts": arp}}
    md_text = build_markdown_report(data)
    return Response(
        md_text,
        mimetype="text/markdown",
        headers={"Content-Disposition": "attachment; filename=harmattan_report.md"},
    )
