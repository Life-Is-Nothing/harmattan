#!/usr/bin/env python3
"""
HARMATTAN v3 — Professional Network Intelligence Suite
======================================================
Audit réseau : ARP enrichi, nmap async, topologie, surface d'attaque,
CVE (NVD + cache), capture trafic, outils pro, rapports, persistance.

Usage strictement réservé à l'audit de réseaux autorisés.

Auteur : Mohamed Adoungouss Ibrahim / NACF
"""
from __future__ import annotations

import csv
import io
import json
import secrets
from datetime import datetime
from functools import wraps

from flask import Flask, Response, g, jsonify, render_template, request

from core import db
from core.config import (
    API_TOKEN,
    AUTO_TOKEN,
    HOST,
    PORT,
    SECRET_KEY,
    VERSION,
    ensure_dirs,
)
from core.jobs import manager as job_manager
from core.logging_setup import get_logger, setup_logging
from core.state import state
from core.validation import (
    ValidationError,
    validate_bpf_filter,
    validate_cidr,
    validate_count,
    validate_iface,
    validate_port,
    validate_target,
)
from core.alerts import notify as alert_notify
from modules import (
    arp_scanner,
    attack_surface,
    network_info,
    nmap_scanner,
    report,
    topology,
    tools,
    vuln_scanner,
)
from modules.diff_scan import diff_arp
from modules.mdns_discovery import discover_mdns_ssdp
from modules.traffic_analyzer import TrafficCapture

setup_logging()
log = get_logger("harmattan.app")
ensure_dirs()
db.init_db()

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["JSON_SORT_KEYS"] = False

# Runtime token (env or auto-generated for local security)
_RUNTIME_TOKEN = API_TOKEN
if not _RUNTIME_TOKEN and AUTO_TOKEN:
    _RUNTIME_TOKEN = secrets.token_urlsafe(24)


def api_response(data=None, error=None, message=None, status=200, **extra):
    body = {"ok": error is None}
    if error:
        body["error"] = error
    if message:
        body["message"] = message
    if data is not None:
        body["data"] = data
    body.update(extra)
    return jsonify(body), status


def require_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _RUNTIME_TOKEN:
            return fn(*args, **kwargs)
        # static / index exempt handled by before_request
        token = (
            request.headers.get("X-Harmattan-Token")
            or request.args.get("token")
            or request.cookies.get("harmattan_token")
        )
        if token != _RUNTIME_TOKEN:
            return api_response(error="unauthorized", message="Token invalide.", status=401)
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def _auth_gate():
    if request.path == "/" or request.path.startswith("/static"):
        return None
    if not request.path.startswith("/api"):
        return None
    # allow health without token for monitoring
    if request.path == "/api/health":
        return None
    if not _RUNTIME_TOKEN:
        return None
    token = (
        request.headers.get("X-Harmattan-Token")
        or request.args.get("token")
        or request.cookies.get("harmattan_token")
    )
    if token != _RUNTIME_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized", "message": "Token requis."}), 401
    return None


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Harmattan-Version"] = VERSION
    if _RUNTIME_TOKEN and request.path == "/":
        resp.set_cookie(
            "harmattan_token",
            _RUNTIME_TOKEN,
            httponly=True,
            samesite="Strict",
            max_age=86400 * 7,
        )
    return resp


@app.errorhandler(ValidationError)
def _validation_error(e: ValidationError):
    return api_response(error=e.code, message=e.message, status=400)


@app.errorhandler(Exception)
def _unhandled(e: Exception):
    log.exception("Unhandled error")
    return api_response(error="internal", message=str(e), status=500)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    snap = network_info.snapshot()
    state.set("last_network", snap)
    db.save_scan("network", snap)
    return render_template(
        "index.html",
        default_subnet=snap.get("subnet") or network_info.get_local_subnet(),
        version=VERSION,
        token=_RUNTIME_TOKEN or "",
    )


# ---------------------------------------------------------------------------
# Health / system
# ---------------------------------------------------------------------------
@app.route("/api/health")
def api_health():
    return jsonify({
        "ok": True,
        "version": VERSION,
        "time": datetime.now().isoformat(timespec="seconds"),
    })


@app.route("/api/system-check")
def api_system_check():
    snap = network_info.snapshot()
    return jsonify({
        "scapy": arp_scanner.SCAPY_AVAILABLE,
        "nmap": nmap_scanner.nmap_available(),
        "local_subnet": snap.get("subnet"),
        "local_ip": snap.get("local_ip"),
        "gateway": snap.get("gateway"),
        "ssid": snap.get("ssid"),
        "interfaces": snap.get("interfaces", []),
        "running_as_root": snap.get("running_as_root"),
        "version": VERSION,
        "auth_enabled": bool(_RUNTIME_TOKEN),
    })


@app.route("/api/network-info")
def api_network_info():
    iface = validate_iface(request.args.get("iface") or None)
    snap = network_info.snapshot(iface)
    state.set("last_network", snap)
    return jsonify(snap)


@app.route("/api/interfaces")
def api_interfaces():
    return jsonify({"interfaces": network_info.get_interfaces()})


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------
@app.route("/api/jobs")
def api_jobs_list():
    return jsonify({"jobs": job_manager.list_jobs()})


@app.route("/api/jobs/<job_id>")
def api_job_get(job_id: str):
    job = job_manager.get(job_id)
    if not job:
        return api_response(error="not_found", message="Job introuvable.", status=404)
    return jsonify(job.to_dict(include_result=True))


@app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
def api_job_cancel(job_id: str):
    if job_manager.cancel(job_id):
        return jsonify({"ok": True, "message": "Annulation demandée."})
    return api_response(error="not_found", message="Job introuvable.", status=404)


# ---------------------------------------------------------------------------
# ARP (async job)
# ---------------------------------------------------------------------------
def _do_arp_scan(subnet, iface, enrich, light, progress=None):
    prev = state.get("last_arp")
    result = arp_scanner.arp_scan(
        subnet, iface=iface, enrich=enrich, light=light, progress=progress
    )
    if not result.get("error"):
        if prev:
            state.set("prev_arp", prev)
            result["diff"] = diff_arp(prev, result)
        state.set("last_arp", result)
        db.save_scan("arp", result)
        new_devs = db.upsert_hosts(result.get("hosts", []))
        state.set("new_devices", new_devs)
        result["new_devices"] = new_devs
        attack = attack_surface.build_attack_surface(
            result.get("hosts", []),
            (state.get("last_nmap") or {}).get("hosts", []),
        )
        state.set("last_attack", attack)
        db.save_scan("attack", attack)
        db.push_history("arp", f"{result.get('count', 0)} hôte(s) sur {subnet}")
        if new_devs:
            alert_notify(
                f"⚠ {len(new_devs)} nouvel(aux) appareil(s): "
                + ", ".join(d.get("ip", "?") for d in new_devs[:8]),
                source="network",
            )
        elif result.get("diff") and result["diff"]["summary"].get("appeared"):
            alert_notify(
                f"ARP diff: +{result['diff']['summary']['appeared']} "
                f"/-{result['diff']['summary']['disappeared']} hôtes",
                source="network",
            )
    return result


@app.route("/api/arp-scan", methods=["POST"])
def api_arp_scan():
    data = request.get_json(force=True, silent=True) or {}
    iface = validate_iface(data.get("iface") or None)
    subnet = data.get("subnet") or network_info.get_local_subnet(iface)
    subnet = validate_cidr(subnet)
    enrich = bool(data.get("enrich", True))
    light = bool(data.get("light", False))
    async_mode = bool(data.get("async", True))

    if not async_mode:
        result = _do_arp_scan(subnet, iface, enrich, light)
        return jsonify(result)

    job = job_manager.submit(
        "arp",
        _do_arp_scan,
        subnet,
        iface,
        enrich,
        light,
        message=f"ARP {subnet}",
    )
    return jsonify({"ok": True, "job_id": job.id, "status": job.status.value})


# ---------------------------------------------------------------------------
# Home pipeline
# ---------------------------------------------------------------------------
def _do_home_scan(iface, subnet, nmap_gateway, nmap_profile, progress=None):
    if progress:
        progress(5, "Contexte réseau…")
    net = network_info.snapshot(iface)
    state.set("last_network", net)
    db.save_scan("network", net)

    if progress:
        progress(15, "Scan ARP…")
    arp = arp_scanner.arp_scan(subnet, iface=iface, enrich=True, progress=progress)
    state.set("last_arp", arp)
    if arp.get("error"):
        return {"error": arp["error"], "message": arp.get("message"), "network": net, "arp": arp}

    db.save_scan("arp", arp)
    new_devs = db.upsert_hosts(arp.get("hosts", []))
    arp["new_devices"] = new_devs
    state.set("new_devices", new_devs)

    nmap_result = None
    gateway = net.get("gateway") or arp.get("gateway")
    if nmap_gateway and gateway:
        if progress:
            progress(60, f"nmap gateway {gateway}…")
        nmap_result = nmap_scanner.run_scan(gateway, profile=nmap_profile, progress=progress)
        state.set("last_nmap", nmap_result)
        if not nmap_result.get("error"):
            db.save_scan("nmap", nmap_result)

    if progress:
        progress(90, "Surface d'attaque…")
    attack = attack_surface.build_attack_surface(
        arp.get("hosts", []),
        (nmap_result or {}).get("hosts", []),
    )
    state.set("last_attack", attack)
    db.save_scan("attack", attack)
    graph = topology.build_graph(arp.get("hosts", []), (nmap_result or {}).get("hosts", []))

    payload = {
        "network": net,
        "arp": arp,
        "nmap": nmap_result,
        "attack": attack,
        "topology": graph,
        "new_devices": new_devs,
    }
    state.set("last_home", payload)
    db.push_history("home", f"Scan maison {subnet} — {arp.get('count', 0)} appareils")
    if progress:
        progress(100, "Terminé")
    return payload


@app.route("/api/home-scan", methods=["POST"])
def api_home_scan():
    data = request.get_json(force=True, silent=True) or {}
    iface = validate_iface(data.get("iface") or None)
    subnet = data.get("subnet") or network_info.get_local_subnet(iface)
    subnet = validate_cidr(subnet)
    nmap_gateway = bool(data.get("nmap_gateway", True))
    nmap_profile = data.get("nmap_profile", "quick")
    async_mode = bool(data.get("async", True))

    if not async_mode:
        return jsonify(_do_home_scan(iface, subnet, nmap_gateway, nmap_profile))

    job = job_manager.submit(
        "home",
        _do_home_scan,
        iface,
        subnet,
        nmap_gateway,
        nmap_profile,
        message=f"Scan maison {subnet}",
    )
    return jsonify({"ok": True, "job_id": job.id, "status": job.status.value})


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------
def _do_nmap(target, profile, custom_args, progress=None):
    result = nmap_scanner.run_scan(target, profile=profile, custom_args=custom_args, progress=progress)
    if not result.get("error"):
        state.set("last_nmap", result)
        db.save_scan("nmap", result)
        attack = attack_surface.build_attack_surface(
            (state.get("last_arp") or {}).get("hosts", []),
            result.get("hosts", []),
        )
        state.set("last_attack", attack)
        db.save_scan("attack", attack)
        db.push_history("nmap", f"{profile} → {target}")
    return result


@app.route("/api/nmap-scan", methods=["POST"])
def api_nmap_scan():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target")
    if not target:
        return api_response(error="missing_target", message="Cible manquante.", status=400)
    target = validate_target(target)
    profile = data.get("profile", "quick")
    custom_args = data.get("custom_args", "") or ""
    async_mode = bool(data.get("async", True))

    if not async_mode:
        return jsonify(_do_nmap(target, profile, custom_args))

    job = job_manager.submit(
        "nmap",
        _do_nmap,
        target,
        profile,
        custom_args,
        message=f"nmap {profile} → {target}",
    )
    return jsonify({"ok": True, "job_id": job.id, "status": job.status.value})


@app.route("/api/nmap-profiles")
def api_nmap_profiles():
    return jsonify({"profiles": nmap_scanner.list_profiles()})


# ---------------------------------------------------------------------------
# Vuln
# ---------------------------------------------------------------------------
def _do_vuln(hosts, progress=None):
    report_data = vuln_scanner.correlate_scan_results(hosts, progress=progress)
    state.set("last_vuln", report_data)
    db.save_scan("vuln", report_data)
    db.push_history("vuln", f"{report_data.get('total_findings', 0)} CVE")
    return report_data


@app.route("/api/vuln-scan", methods=["POST"])
def api_vuln_scan():
    data = request.get_json(force=True, silent=True) or {}
    hosts = data.get("hosts")
    if not hosts:
        last = state.get("last_nmap")
        if not last or not last.get("hosts"):
            return api_response(
                error="no_data",
                message="Lancez d'abord un scan nmap avec détection de services (-sV).",
                status=400,
            )
        hosts = last["hosts"]

    async_mode = bool(data.get("async", True))
    if not async_mode:
        return jsonify(_do_vuln(hosts))

    job = job_manager.submit("vuln", _do_vuln, hosts, message="Corrélation CVE NVD…")
    return jsonify({"ok": True, "job_id": job.id, "status": job.status.value})


# ---------------------------------------------------------------------------
# Attack surface / topology
# ---------------------------------------------------------------------------
@app.route("/api/attack-surface")
def api_attack_surface():
    attack = attack_surface.build_attack_surface(
        (state.get("last_arp") or {}).get("hosts", []),
        (state.get("last_nmap") or {}).get("hosts", []),
    )
    state.set("last_attack", attack)
    return jsonify(attack)


@app.route("/api/topology")
def api_topology():
    arp_hosts = (state.get("last_arp") or {}).get("hosts", [])
    nmap_hosts = (state.get("last_nmap") or {}).get("hosts", [])
    graph = topology.build_graph(arp_hosts, nmap_hosts)
    return jsonify(graph)


@app.route("/api/topology/export.csv")
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


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@app.route("/api/tools/ping", methods=["POST"])
def api_ping():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or data.get("target")
    if not ip:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.ping_host(ip, count=validate_count(data.get("count", 3))))


@app.route("/api/tools/traceroute", methods=["POST"])
def api_traceroute():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or data.get("target")
    if not ip:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.traceroute(ip, max_hops=validate_count(data.get("max_hops", 20), 20, 1, 64)))


@app.route("/api/tools/banner", methods=["POST"])
def api_banner():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or data.get("target")
    port = data.get("port", 80)
    if not ip:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.grab_banner(ip, int(port)))


@app.route("/api/tools/dns", methods=["POST"])
def api_dns():
    data = request.get_json(force=True, silent=True) or {}
    q = data.get("query") or data.get("ip") or data.get("target")
    if not q:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.dns_lookup(q))


@app.route("/api/tools/tls", methods=["POST"])
def api_tls():
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host") or data.get("ip") or data.get("target")
    port = data.get("port", 443)
    if not host:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.tls_inspect(host, int(port)))


# ---------------------------------------------------------------------------
# Traffic
# ---------------------------------------------------------------------------
@app.route("/api/traffic/start", methods=["POST"])
def api_traffic_start():
    data = request.get_json(force=True, silent=True) or {}
    iface = validate_iface(data.get("iface") or None)
    bpf_filter = validate_bpf_filter(data.get("filter", "") or "")

    cap = state.capture
    if cap and cap.running:
        return jsonify({"message": "Capture déjà en cours.", "running": True})

    cap = TrafficCapture(iface=iface, bpf_filter=bpf_filter)
    cap.start()
    state.capture = cap
    db.push_history("traffic", "Capture démarrée")
    return jsonify({"message": "Capture démarrée.", "started": datetime.now().isoformat()})


@app.route("/api/traffic/stop", methods=["POST"])
def api_traffic_stop():
    cap = state.capture
    if cap:
        cap.stop()
    db.push_history("traffic", "Capture arrêtée")
    return jsonify({"message": "Capture arrêtée."})


@app.route("/api/traffic/snapshot")
def api_traffic_snapshot():
    cap = state.capture
    if not cap:
        return jsonify({
            "running": False, "error": None, "total_packets": 0,
            "recent_packets": [], "top_flows": [], "bytes_total": 0,
        })
    return jsonify(cap.snapshot())


@app.route("/api/traffic/export.csv")
def api_traffic_export():
    cap = state.capture
    if not cap:
        return Response(
            "time,src,dst,protocol,sport,dport,length\n",
            mimetype="text/csv",
        )
    return Response(
        cap.export_csv(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=harmattan_traffic.csv"},
    )


@app.route("/api/traffic/export.pcap")
def api_traffic_export_pcap():
    cap = state.capture
    if not cap:
        return api_response(error="no_capture", message="Aucune capture active.", status=400)
    try:
        data = cap.export_pcap_bytes()
    except Exception as e:
        return api_response(error="pcap_failed", message=str(e), status=400)
    return Response(
        data,
        mimetype="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": "attachment; filename=harmattan_traffic.pcap"},
    )


@app.route("/api/diff/arp")
def api_diff_arp():
    """Diff between previous and last ARP scan (or last two DB scans)."""
    prev = state.get("prev_arp")
    last = state.get("last_arp")
    if not last:
        last = db.get_last_scan("arp")
    if not prev and last:
        # try two last from DB is not stored as multi - use empty
        prev = state.get("prev_arp") or {"hosts": []}
    if not last:
        return api_response(error="no_data", message="Lancez au moins un scan ARP.", status=400)
    return jsonify(diff_arp(prev, last))


@app.route("/api/mdns-ssdp", methods=["POST"])
def api_mdns_ssdp():
    data = request.get_json(force=True, silent=True) or {}
    async_mode = bool(data.get("async", True))
    timeout = float(data.get("timeout", 2.5))

    def work(progress=None):
        r = discover_mdns_ssdp(timeout=timeout, progress=progress)
        state.set("last_mdns", r)
        db.save_scan("mdns", r)
        db.push_history("mdns", f"{r.get('count', 0)} annonces mDNS/SSDP")
        return r

    if not async_mode:
        return jsonify(work())
    job = job_manager.submit("mdns", work, message="mDNS/SSDP discovery")
    return jsonify({"ok": True, "job_id": job.id, "status": job.status.value})


# ---------------------------------------------------------------------------
# Report / history / hosts / session
# ---------------------------------------------------------------------------
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


@app.route("/api/report.html")
def api_report_html():
    network, arp, nmap, vuln, attack = _report_bundle()
    meta = _report_meta_from_request()
    html = report.build_html_report(network, arp, nmap, vuln, attack, **meta)
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": "attachment; filename=harmattan_report.html"},
    )


@app.route("/api/report.json")
def api_report_json():
    network, arp, nmap, vuln, attack = _report_bundle()
    meta = _report_meta_from_request()
    payload = report.build_json_report(network, arp, nmap, vuln, attack, **meta)
    return Response(
        json.dumps(payload, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=harmattan_report.json"},
    )


@app.route("/api/report.pdf")
def api_report_pdf():
    network, arp, nmap, vuln, attack = _report_bundle()
    meta = _report_meta_from_request()
    pdf = report.build_pdf_report(network, arp, nmap, vuln, attack, **meta)
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=harmattan_report.pdf"},
    )


@app.route("/api/report.docx")
def api_report_docx():
    network, arp, nmap, vuln, attack = _report_bundle()
    meta = _report_meta_from_request()
    docx_bytes = report.build_docx_report(network, arp, nmap, vuln, attack, **meta)
    return Response(
        docx_bytes,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": "attachment; filename=harmattan_report.docx"},
    )


@app.route("/api/history")
def api_history():
    return jsonify({"history": db.get_history(40)})


@app.route("/api/known-hosts")
def api_known_hosts():
    return jsonify({"hosts": db.list_known_hosts(), "new_devices": state.get("new_devices") or []})


@app.route("/api/session/export")
def api_session_export():
    payload = db.export_session_json()
    # merge in-memory latest
    for key in ("last_arp", "last_nmap", "last_vuln", "last_attack", "last_network"):
        val = state.get(key)
        if val:
            payload[key] = val
    return Response(
        json.dumps(payload, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=harmattan_session.json"},
    )


@app.route("/api/host/<path:ip>")
def api_host_detail(ip: str):
    """Aggregate all known data for one host."""
    try:
        ip = validate_target(ip)
    except ValidationError as e:
        return api_response(error=e.code, message=e.message, status=400)

    arp_hosts = (state.get("last_arp") or {}).get("hosts", [])
    nmap_hosts = (state.get("last_nmap") or {}).get("hosts", [])
    attack = state.get("last_attack") or {}
    vuln = state.get("last_vuln") or {}

    arp = next((h for h in arp_hosts if h.get("ip") == ip), None)
    nmap = next((h for h in nmap_hosts if h.get("ip") == ip), None)
    atk = next((h for h in attack.get("hosts", []) if h.get("ip") == ip), None)
    vul = next((h for h in vuln.get("hosts", []) if h.get("ip") == ip), None)

    return jsonify({
        "ip": ip,
        "arp": arp,
        "nmap": nmap,
        "attack": atk,
        "vuln": vul,
    })


if __name__ == "__main__":
    print("=" * 64)
    print(f"  HARMATTAN v{VERSION} — Network Intelligence Suite")
    print(f"  Interface web : http://{HOST}:{PORT}")
    print("  NOTE : ARP scan et capture de trafic nécessitent 'sudo'")
    if _RUNTIME_TOKEN:
        print(f"  API Token     : {_RUNTIME_TOKEN}")
        print("  (header X-Harmattan-Token ou cookie automatique)")
    print("=" * 64)
    log.info("Starting HARMATTAN v%s on %s:%s", VERSION, HOST, PORT)
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
