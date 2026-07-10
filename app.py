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
import os
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
    REPORTS_DIR,
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
    from modules import monitor as mon

    mon_st = {}
    try:
        mon_st = mon.status()
    except Exception:
        mon_st = {"running": False}
    return jsonify({
        "ok": True,
        "version": VERSION,
        "time": datetime.now().isoformat(timespec="seconds"),
        "auth_enabled": bool(_RUNTIME_TOKEN),
        "scapy": arp_scanner.SCAPY_AVAILABLE,
        "nmap": nmap_scanner.nmap_available(),
        "jobs_running": sum(
            1 for j in (job_manager.list_jobs() or [])
            if (j.get("status") if isinstance(j, dict) else getattr(j, "status", None)) in ("running", "pending", "queued")
        ),
        "monitor": mon_st,
        "has_arp": bool((state.get("last_arp") or {}).get("hosts")),
        "has_nmap": bool((state.get("last_nmap") or {}).get("hosts")),
        "known_hosts": len(db.list_known_hosts()),
        "overrides": len(db.list_overrides()),
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
def _push_sahel_payload(url: str | None = None) -> dict:
    """Build current session payload and push to Sahel (best-effort)."""
    import urllib.request

    base = (
        (url or db.get_setting("sahel_url") or os.environ.get("SAHEL_URL") or "http://127.0.0.1:8099")
    ).rstrip("/")
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
        "source": "harmattan-full-chain",
        "subnet": (arp.get("meta") or {}).get("subnet") or network_info.get_local_subnet(),
        "gateway": network_info.get_default_gateway(),
    }
    for path in ("/api/import/harmattan", "/api/correlate/harmattan", "/api/events", "/api/ingest"):
        try:
            body = json.dumps(payload).encode()
            req = urllib.request.Request(
                base + path,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                if 200 <= resp.status < 300:
                    return {
                        "ok": True,
                        "url": base + path,
                        "hosts": len(payload["hosts"]),
                        "path": path,
                    }
        except Exception as e:
            last_err = str(e)[:120]
            continue
    out = REPORTS_DIR / f"sahel_push_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        out = None
    return {
        "ok": False,
        "hosts": len(payload["hosts"]),
        "file": out.name if out else None,
        "error": locals().get("last_err") or "sahel unreachable",
    }


def _do_home_scan(iface, subnet, nmap_gateway, nmap_profile, full_chain=False, progress=None):
    """ARP → nmap gateway → surface → topologie → (optionnel) push Sahel."""
    if progress:
        progress(3, "Contexte réseau…")
    net = network_info.snapshot(iface)
    state.set("last_network", net)
    db.save_scan("network", net)

    if progress:
        progress(12, "Scan ARP…")
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
            progress(55, f"nmap gateway {gateway}…")
        nmap_result = nmap_scanner.run_scan(gateway, profile=nmap_profile, progress=progress)
        state.set("last_nmap", nmap_result)
        if not nmap_result.get("error"):
            db.save_scan("nmap", nmap_result)

    if progress:
        progress(82, "Surface d'attaque…")
    attack = attack_surface.build_attack_surface(
        arp.get("hosts", []),
        (nmap_result or {}).get("hosts", []),
    )
    state.set("last_attack", attack)
    db.save_scan("attack", attack)

    if progress:
        progress(88, "Topologie…")
    graph = topology.build_graph(arp.get("hosts", []), (nmap_result or {}).get("hosts", []))
    state.set("last_topology", graph)

    sahel_push = None
    if full_chain:
        if progress:
            progress(93, "Push Sahel…")
        sahel_push = _push_sahel_payload()
        db.push_history(
            "sahel",
            f"Full-chain push: {'OK' if sahel_push.get('ok') else 'local'} · {sahel_push.get('hosts', 0)} hosts",
        )

    payload = {
        "network": net,
        "arp": arp,
        "nmap": nmap_result,
        "attack": attack,
        "topology": graph,
        "new_devices": new_devs,
        "full_chain": bool(full_chain),
        "sahel_push": sahel_push,
        "steps": [
            "network",
            "arp",
            "nmap" if nmap_gateway else None,
            "attack",
            "topology",
            "sahel" if full_chain else None,
        ],
    }
    payload["steps"] = [s for s in payload["steps"] if s]
    state.set("last_home", payload)
    label = "Full-chain" if full_chain else "Scan maison"
    db.push_history("home", f"{label} {subnet} — {arp.get('count', 0)} appareils")
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
    full_chain = bool(data.get("full_chain", True))  # fluidité: chaîne complète par défaut

    if not async_mode:
        return jsonify(_do_home_scan(iface, subnet, nmap_gateway, nmap_profile, full_chain))

    kind = "full-chain" if full_chain else "home"
    job = job_manager.submit(
        kind,
        _do_home_scan,
        iface,
        subnet,
        nmap_gateway,
        nmap_profile,
        full_chain,
        message=f"{'Full-chain' if full_chain else 'Scan maison'} {subnet}",
    )
    return jsonify({"ok": True, "job_id": job.id, "status": job.status.value, "full_chain": full_chain})


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
    arp_hosts = db.apply_overrides_to_hosts(arp_hosts)
    graph = topology.build_graph(arp_hosts, nmap_hosts)
    return jsonify(graph)


@app.route("/api/host/override", methods=["POST"])
def api_host_override():
    data = request.get_json(force=True, silent=True) or {}
    key = data.get("key") or data.get("mac") or data.get("ip")
    if not key:
        return api_response(error="missing_key", status=400)
    tags = data.get("tags")
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.replace(";", ",").split(",") if t.strip()]
    result = db.set_host_override(
        key,
        role=data.get("role"),
        tags=tags,
        notes=data.get("notes"),
        label=data.get("label"),
    )
    # refresh last_arp roles in memory
    last = state.get("last_arp") or {}
    if last.get("hosts"):
        last = dict(last)
        last["hosts"] = db.apply_overrides_to_hosts(last["hosts"])
        state.set("last_arp", last)
    return jsonify(result)


@app.route("/api/host/override", methods=["DELETE"])
def api_host_override_delete():
    data = request.get_json(force=True, silent=True) or {}
    key = data.get("key") or data.get("mac") or data.get("ip") or request.args.get("key")
    if not key:
        return api_response(error="missing_key", status=400)
    ok = db.delete_host_override(key)
    last = state.get("last_arp") or {}
    if last.get("hosts"):
        # re-apply remaining overrides only
        last = dict(last)
        last["hosts"] = db.apply_overrides_to_hosts(last["hosts"])
        state.set("last_arp", last)
    return api_response(message="Override supprimé" if ok else "Introuvable", data={"deleted": ok})


@app.route("/api/overrides")
def api_overrides():
    return jsonify({"overrides": db.list_overrides()})


@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    return jsonify({
        "sahel_url": db.get_setting("sahel_url", os.environ.get("SAHEL_URL", "http://127.0.0.1:8099")),
        "theme": db.get_setting("theme", "dark"),
    })


@app.route("/api/settings", methods=["POST"])
def api_settings_set():
    data = request.get_json(force=True, silent=True) or {}
    for k in ("sahel_url", "theme"):
        if k in data and data[k] is not None:
            db.set_setting(k, str(data[k]))
    return api_response(message="Paramètres enregistrés", data={
        "sahel_url": db.get_setting("sahel_url", ""),
        "theme": db.get_setting("theme", "dark"),
    })


@app.route("/api/scans")
def api_scans_list():
    kind = request.args.get("kind")
    return jsonify({"scans": db.list_scans(kind=kind, limit=int(request.args.get("limit") or 40))})


@app.route("/api/scans/<int:scan_id>")
def api_scan_get(scan_id: int):
    s = db.get_scan(scan_id)
    if not s:
        return api_response(error="not_found", status=404)
    return jsonify(s)


@app.route("/api/scans/<int:scan_id>/load", methods=["POST"])
def api_scan_load(scan_id: int):
    """Recharge un scan historique dans le state runtime."""
    s = db.get_scan(scan_id)
    if not s:
        return api_response(error="not_found", status=404)
    kind = s["kind"]
    payload = s["payload"]
    if kind == "arp":
        if isinstance(payload, dict) and payload.get("hosts"):
            payload = dict(payload)
            payload["hosts"] = db.apply_overrides_to_hosts(payload["hosts"])
        state.set("last_arp", payload)
    elif kind == "nmap":
        state.set("last_nmap", payload)
    elif kind == "attack":
        state.set("last_attack", payload)
    elif kind == "vuln":
        state.set("last_vuln", payload)
    elif kind == "network":
        state.set("last_network", payload)
    return api_response(message=f"Scan {scan_id} ({kind}) chargé", data={"kind": kind, "id": scan_id})


@app.route("/api/export/sahel/push", methods=["POST"])
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


@app.route("/api/monitor/status")
def api_monitor_status():
    from modules import monitor as mon

    return jsonify(mon.status())


@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    from modules import monitor as mon

    data = request.get_json(force=True, silent=True) or {}
    ok, msg = mon.start(interval=int(data.get("interval") or 60))
    return api_response(message=msg, status=200 if ok else 400)


@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    from modules import monitor as mon

    ok, msg = mon.stop()
    return api_response(message=msg, status=200 if ok else 400)


@app.route("/api/scheduler/status")
def api_scheduler_status():
    from modules import scheduler as sched

    return jsonify(sched.status())


@app.route("/api/scheduler/start", methods=["POST"])
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


@app.route("/api/scheduler/stop", methods=["POST"])
def api_scheduler_stop():
    from modules import scheduler as sched

    ok, msg = sched.stop()
    return api_response(message=msg, status=200 if ok else 400, data=sched.status())


@app.route("/api/export/sahel")
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


@app.route("/api/export/pt-scope")
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
    import os as _os

    data = request.get_json(force=True, silent=True) or {}
    raw_iface = (data.get("iface") or "").strip() or None
    iface = validate_iface(raw_iface) if raw_iface else network_info.suggest_capture_iface()
    bpf_filter = validate_bpf_filter(data.get("filter", "") or "")
    is_root = hasattr(_os, "geteuid") and _os.geteuid() == 0

    cap = state.capture
    if cap and cap.running:
        return jsonify({
            "message": "Capture déjà en cours.",
            "running": True,
            "iface": getattr(cap, "iface", None),
        })

    cap = TrafficCapture(iface=iface, bpf_filter=bpf_filter)
    cap.start()
    state.capture = cap
    db.push_history("traffic", f"Capture démarrée ({iface or 'auto'})")
    # court délai pour remonter PermissionError du thread
    import time as _time
    _time.sleep(0.35)
    snap = cap.snapshot()
    msg = "Capture démarrée."
    if snap.get("error"):
        msg = snap["error"]
    elif not is_root:
        msg = (
            f"Capture démarrée sur {iface or 'auto'} — sans root le buffer peut rester vide. "
            "Préférez « Capture 10 s » avec sudo, ou exportez un PCAP importé."
        )
    return jsonify({
        "message": msg,
        "started": datetime.now().isoformat(),
        "iface": iface,
        "running_as_root": is_root,
        "error": snap.get("error"),
        "running": cap.running,
    })


@app.route("/api/traffic/oneshot", methods=["POST"])
def api_traffic_oneshot():
    """Capture courte bloquante (défaut 10 s) — le plus fiable en lab."""
    import os as _os

    data = request.get_json(force=True, silent=True) or {}
    raw_iface = (data.get("iface") or "").strip() or None
    iface = validate_iface(raw_iface) if raw_iface else network_info.suggest_capture_iface()
    bpf_filter = validate_bpf_filter(data.get("filter", "") or "")
    seconds = max(1, min(int(data.get("seconds") or 10), 60))
    is_root = hasattr(_os, "geteuid") and _os.geteuid() == 0

    # stop previous continuous capture
    if state.capture and state.capture.running:
        state.capture.stop()

    cap = TrafficCapture(iface=iface, bpf_filter=bpf_filter)
    snap = cap.capture_oneshot(seconds)
    state.capture = cap
    db.push_history("traffic", f"Oneshot {seconds}s · {snap.get('total_packets', 0)} pkts · {iface}")
    if snap.get("error"):
        return api_response(
            error="capture_failed",
            message=snap["error"],
            status=400,
            snapshot=snap,
            iface=iface,
            running_as_root=is_root,
        )
    if snap.get("total_packets", 0) == 0 and not is_root:
        return jsonify({
            "message": (
                "0 paquet capturé. Sans privilèges root, la capture live est souvent bloquée. "
                "Relance avec: sudo ./harmattan.sh  — ou importe un PCAP."
            ),
            "warning": "no_packets_no_root",
            "iface": iface,
            "seconds": seconds,
            "running_as_root": is_root,
            **snap,
        })
    return jsonify({
        "message": f"Capture {seconds}s terminée — {snap.get('total_packets', 0)} paquets.",
        "iface": iface,
        "seconds": seconds,
        "running_as_root": is_root,
        **snap,
    })


@app.route("/api/traffic/stop", methods=["POST"])
def api_traffic_stop():
    cap = state.capture
    if cap:
        cap.stop()
    db.push_history("traffic", "Capture arrêtée")
    return jsonify({"message": "Capture arrêtée."})


@app.route("/api/traffic/packets")
def api_traffic_packets():
    """Liste paquets style Wireshark (+ display filter)."""
    cap = state.capture
    if not cap:
        return jsonify({
            "total": 0, "packets": [], "running": False,
            "buffer_total": 0, "bytes_total": 0, "packets_total": 0,
        })
    offset = max(0, int(request.args.get("offset") or 0))
    limit = max(1, min(int(request.args.get("limit") or 300), 1000))
    dfilt = request.args.get("filter") or request.args.get("display_filter") or ""
    return jsonify(cap.list_packets(offset=offset, limit=limit, display_filter=dfilt))


@app.route("/api/traffic/packet/<int:no>")
def api_traffic_packet_detail(no: int):
    """Détail d'un paquet : layers + hex dump."""
    cap = state.capture
    if not cap:
        return api_response(error="no_capture", status=404)
    p = cap.get_packet(no)
    if not p:
        return api_response(error="not_found", message=f"Paquet #{no} introuvable", status=404)
    return jsonify(p)


@app.route("/api/traffic/follow/<int:no>")
def api_traffic_follow(no: int):
    """Follow TCP/UDP stream (Wireshark)."""
    cap = state.capture
    if not cap:
        return api_response(error="no_capture", status=404)
    result = cap.follow_stream(no)
    status = 200 if result.get("ok") else 400
    return jsonify(result), status


@app.route("/api/traffic/follow/<int:no>/export.txt")
def api_traffic_follow_export_txt(no: int):
    cap = state.capture
    if not cap:
        return api_response(error="no_capture", status=404)
    try:
        text = cap.export_stream_text(no)
    except Exception as e:
        return api_response(error="export_failed", message=str(e), status=400)
    # also save under reports/
    try:
        out = REPORTS_DIR / f"stream_{no}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        out.write_text(text, encoding="utf-8")
    except Exception:
        out = None
    return Response(
        text,
        mimetype="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename=harmattan_stream_{no}.txt",
            **({"X-Saved-As": out.name} if out else {}),
        },
    )


@app.route("/api/traffic/follow/<int:no>/export.json")
def api_traffic_follow_export_json(no: int):
    cap = state.capture
    if not cap:
        return api_response(error="no_capture", status=404)
    try:
        payload = cap.export_stream_json(no)
    except Exception as e:
        return api_response(error="export_failed", message=str(e), status=400)
    try:
        out = REPORTS_DIR / f"stream_{no}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        out = None
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=harmattan_stream_{no}.json"},
    )


@app.route("/api/sahel/correlate", methods=["POST"])
def api_sahel_correlate():
    """
    Corrélation locale ou push vers Sahel :
    - si body.alerts fourni → local
    - sinon tente fetch Sahel alerts + local, puis push packets to Sahel
    """
    from modules import sahel_correlate

    data = request.get_json(force=True, silent=True) or {}
    cap = state.capture
    packets = []
    if cap:
        packets = cap.packet_index_for_correlation(limit=int(data.get("limit") or 2000))
    elif data.get("packets"):
        packets = data["packets"]

    sahel_url = (
        data.get("url")
        or db.get_setting("sahel_url")
        or os.environ.get("SAHEL_URL")
        or "http://127.0.0.1:8099"
    ).rstrip("/")
    if data.get("url"):
        db.set_setting("sahel_url", sahel_url)

    alerts = data.get("alerts")
    if not alerts:
        alerts = sahel_correlate.fetch_sahel_alerts(sahel_url, limit=150)

    local = sahel_correlate.local_correlate(packets, alerts or [])
    # also push to Sahel for server-side correlation + storage
    hosts = (state.get("last_arp") or {}).get("hosts") or []
    remote = sahel_correlate.push_and_correlate(
        sahel_url,
        packets,
        hosts=hosts,
        extra={"local_matches": local.get("matched"), "version": VERSION},
    )
    db.push_history(
        "correlate",
        f"Corrélation Sahel: local={local.get('matched')} remote_ok={remote.get('ok')}",
    )
    state.set("last_correlation", {"local": local, "remote": remote, "sahel_url": sahel_url})
    return jsonify(
        {
            "ok": True,
            "packets": len(packets),
            "alerts_used": len(alerts or []),
            "local": local,
            "remote": remote,
            "sahel_url": sahel_url,
        }
    )


@app.route("/api/sahel/correlate/last")
def api_sahel_correlate_last():
    return jsonify(state.get("last_correlation") or {"ok": False, "message": "aucune corrélation"})


@app.route("/api/traffic/clear", methods=["POST"])
def api_traffic_clear():
    cap = state.capture
    if not cap:
        return api_response(message="Rien à vider", data={"cleared": False})
    snap = cap.clear()
    db.push_history("traffic", "Buffer trafic vidé")
    return api_response(message="Buffer vidé", data=snap)


@app.route("/api/traffic/proto-stats")
def api_traffic_proto_stats():
    cap = state.capture
    if not cap:
        return jsonify({"protocols": [], "unique": 0})
    return jsonify(cap.protocol_stats())


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
        return api_response(
            error="no_capture",
            message="Aucune capture. Démarrez le trafic quelques secondes avant d'exporter PCAP.",
            status=400,
        )
    try:
        data = cap.export_pcap_bytes()
    except Exception as e:
        log.exception("pcap export failed")
        return api_response(error="pcap_failed", message=str(e), status=400)
    return Response(
        data,
        mimetype="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": "attachment; filename=harmattan_traffic.pcap",
            "Content-Length": str(len(data)),
            "Cache-Control": "no-store",
        },
    )


@app.route("/api/traffic/import.pcap", methods=["POST"])
def api_traffic_import_pcap():
    """Analyse offline d'un fichier PCAP uploadé."""
    f = request.files.get("pcap") or request.files.get("file")
    if not f or not f.filename:
        return api_response(error="no_file", message="Fichier PCAP manquant.", status=400)
    name = (f.filename or "").lower()
    if not name.endswith((".pcap", ".pcapng", ".cap")):
        return api_response(error="bad_format", message="Formats: .pcap / .pcapng / .cap", status=400)
    import tempfile
    import os
    from modules.traffic_analyzer import TrafficCapture

    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="harmattan_up_")
    os.close(fd)
    try:
        f.save(path)
        cap = TrafficCapture()
        snap = cap.load_pcap_file(path)
        # garder en mémoire pour re-export
        state.capture = cap
        db.push_history("traffic", f"Import PCAP {f.filename}: {snap.get('total_packets', 0)} pkts")
        return jsonify({"message": "PCAP importé", "filename": f.filename, **snap})
    except Exception as e:
        log.exception("pcap import failed")
        return api_response(error="pcap_import_failed", message=str(e), status=400)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


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
    result = diff_arp(prev, last)
    result["has_baseline"] = bool(prev and (prev.get("hosts") or prev.get("count")))
    result["prev_count"] = len((prev or {}).get("hosts") or [])
    result["last_count"] = len((last or {}).get("hosts") or [])
    return jsonify(result)


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


# ---------------------------------------------------------------------------
# Discovery advanced: SNMP, NetBIOS, LLDP/CDP, Wi‑Fi
# ---------------------------------------------------------------------------
@app.route("/api/snmp/probe", methods=["POST"])
def api_snmp_probe():
    from modules import snmp_probe

    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target") or data.get("ip")
    if target:
        try:
            target = validate_target(target)
        except ValidationError as e:
            return api_response(error=e.code, message=e.message, status=400)
        result = snmp_probe.probe_host(target)
        state.set("last_snmp", result)
        db.push_history("snmp", f"SNMP {target}: {'OK' if result.get('ok') else 'no reply'}")
        return jsonify(result)

    # batch from last ARP
    hosts = [(h.get("ip") or "") for h in (state.get("last_arp") or {}).get("hosts", []) if h.get("ip")]
    if not hosts:
        return api_response(error="no_hosts", message="Lance un scan ARP d'abord.", status=400)

    def work(progress=None):
        if progress:
            progress(5, f"SNMP probe {len(hosts)} hôtes…")
        out = snmp_probe.probe_many(hosts, max_hosts=int(data.get("max") or 40))
        state.set("last_snmp", out)
        db.save_scan("snmp", out)
        db.push_history("snmp", f"SNMP batch: {out.get('responding', 0)} réponses")
        if progress:
            progress(100, "OK")
        return out

    if data.get("async"):
        job = job_manager.submit("snmp", work)
        return jsonify({"job_id": job.id, "kind": "snmp"})
    return jsonify(work())


@app.route("/api/netbios/probe", methods=["POST"])
def api_netbios_probe():
    from modules import netbios_probe

    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target") or data.get("ip")
    if target:
        try:
            target = validate_target(target)
        except ValidationError as e:
            return api_response(error=e.code, message=e.message, status=400)
        result = netbios_probe.probe(target)
        db.push_history("netbios", f"NetBIOS {target}: {result.get('hostname') or '—'}")
        return jsonify(result)
    hosts = [(h.get("ip") or "") for h in (state.get("last_arp") or {}).get("hosts", []) if h.get("ip")]
    if not hosts:
        return api_response(error="no_hosts", message="Lance un scan ARP d'abord.", status=400)

    def work(progress=None):
        if progress:
            progress(10, "NetBIOS…")
        out = netbios_probe.probe_many(hosts)
        # enrich last_arp hostnames
        last = state.get("last_arp") or {}
        if last.get("hosts") and out.get("hosts"):
            by_ip = {x["ip"]: x for x in out["hosts"]}
            hosts2 = []
            for h in last["hosts"]:
                hh = dict(h)
                nb = by_ip.get(hh.get("ip") or "")
                if nb and nb.get("hostname") and not hh.get("hostname"):
                    hh["hostname"] = nb["hostname"]
                    hh["netbios"] = nb.get("names")
                hosts2.append(hh)
            last = dict(last)
            last["hosts"] = hosts2
            state.set("last_arp", last)
        state.set("last_netbios", out)
        db.save_scan("netbios", out)
        db.push_history("netbios", f"NetBIOS: {out.get('found', 0)} noms")
        if progress:
            progress(100, "OK")
        return out

    if data.get("async", True):
        job = job_manager.submit("netbios", work)
        return jsonify({"job_id": job.id, "kind": "netbios"})
    return jsonify(work())


@app.route("/api/lldp-cdp", methods=["POST"])
def api_lldp_cdp():
    from modules import lldp_cdp

    data = request.get_json(force=True, silent=True) or {}
    iface = validate_iface(data.get("iface") or None)
    timeout = float(data.get("timeout") or 8)

    def work(progress=None):
        out = lldp_cdp.discover(iface=iface, timeout=timeout, progress=progress)
        state.set("last_lldp", out)
        db.save_scan("lldp", out)
        db.push_history("lldp", f"LLDP/CDP: {out.get('count', 0)} voisins")
        return out

    if data.get("async", True):
        job = job_manager.submit("lldp", work)
        return jsonify({"job_id": job.id, "kind": "lldp"})
    return jsonify(work())


@app.route("/api/wifi/scan", methods=["POST"])
def api_wifi_scan():
    from modules import wifi_scan

    data = request.get_json(force=True, silent=True) or {}
    iface = data.get("iface") or None

    def work(progress=None):
        if progress:
            progress(20, "Scan Wi‑Fi…")
        out = wifi_scan.scan(iface=iface)
        state.set("last_wifi", out)
        db.save_scan("wifi", out)
        db.push_history("wifi", f"Wi‑Fi: {out.get('count', 0)} AP")
        if progress:
            progress(100, "OK")
        return out

    if data.get("async", True):
        job = job_manager.submit("wifi", work)
        return jsonify({"job_id": job.id, "kind": "wifi"})
    return jsonify(work())


# ---------------------------------------------------------------------------
# MITRE, scoring, Suricata, exports advanced
# ---------------------------------------------------------------------------
@app.route("/api/mitre")
def api_mitre():
    from modules.mitre_map import map_network
    from modules import attack_surface as asurf

    arp = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    nmap = (state.get("last_nmap") or {}).get("hosts", [])
    attack = state.get("last_attack") or asurf.build_attack_surface(arp, nmap)
    new_devs = state.get("new_devices") or []
    result = map_network(arp, nmap, attack, new_devs)
    state.set("last_mitre", result)
    return jsonify(result)


@app.route("/api/score/hosts", methods=["POST", "GET"])
def api_score_hosts():
    from modules import host_scoring

    arp = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    nmap = (state.get("last_nmap") or {}).get("hosts", [])
    result = host_scoring.score_hosts(arp, nmap)
    state.set("last_scores", result)
    db.push_history(
        "score",
        f"Anomalies: {result.get('anomaly_count', 0)}/{result.get('host_count', 0)} ({result.get('method')})",
    )
    return jsonify(result)


@app.route("/api/suricata/alerts")
def api_suricata_alerts():
    from modules import suricata_feed

    path = request.args.get("path")
    limit = int(request.args.get("limit") or 50)
    return jsonify(suricata_feed.read_alerts(path=path, limit=limit))


@app.route("/api/export/stix")
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


@app.route("/api/export/graphml")
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


@app.route("/api/export/gexf")
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


@app.route("/api/sahel/bridge/status")
def api_sahel_bridge_status():
    from modules import sahel_bridge

    return jsonify(sahel_bridge.status())


@app.route("/api/sahel/bridge/start", methods=["POST"])
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


@app.route("/api/sahel/bridge/stop", methods=["POST"])
def api_sahel_bridge_stop():
    from modules import sahel_bridge

    ok, msg = sahel_bridge.stop()
    return api_response(message=msg, status=200 if ok else 400, data=sahel_bridge.status())


# ---------------------------------------------------------------------------
# L0p4Map parity pack: range map, default-creds, WOL, labels, findings
# ---------------------------------------------------------------------------
@app.route("/api/range-map", methods=["POST"])
def api_range_map():
    """Cartographie multi-plage (ping + traceroute parent) — style L0p4Map."""
    from modules import range_map

    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target") or data.get("subnet") or network_info.get_local_subnet()
    enrich = data.get("enrich", True)

    def work(progress=None):
        out = range_map.map_range(target, enrich=bool(enrich), progress=progress)
        if out.get("hosts"):
            out["hosts"] = db.apply_overrides_to_hosts(out["hosts"])
            state.set("last_arp", {
                "hosts": out["hosts"],
                "count": len(out["hosts"]),
                "meta": {"subnet": target, "via": "range_map", "by_parent": out.get("by_parent")},
            })
            db.save_scan("arp", state.get("last_arp"))
            db.push_history("range", f"Range map {target}: {out.get('alive', 0)} up")
        return out

    if data.get("async", True):
        job = job_manager.submit("range_map", work)
        return jsonify({"job_id": job.id, "kind": "range_map"})
    return jsonify(work())


@app.route("/api/default-creds", methods=["POST"])
def api_default_creds():
    """Scan inventaire pour équipements à risque credentials usine."""
    from modules import default_creds

    data = request.get_json(force=True, silent=True) or {}
    hosts = (state.get("last_arp") or {}).get("hosts") or []
    if data.get("hosts"):
        hosts = data["hosts"]
    if not hosts:
        return api_response(error="no_hosts", message="Lance un scan ARP d'abord.", status=400)

    def work(progress=None):
        if progress:
            progress(10, "Banners / signatures…")
        out = default_creds.scan_hosts(
            hosts, max_hosts=int(data.get("max") or 40), deep=bool(data.get("deep", True))
        )
        # merge flags into last_arp
        by_ip = {h["ip"]: h for h in out.get("hosts") or []}
        last = state.get("last_arp") or {}
        if last.get("hosts"):
            merged = []
            for h in last["hosts"]:
                hh = dict(h)
                if hh.get("ip") in by_ip:
                    hh["default_cred_flags"] = by_ip[hh["ip"]]["flags"]
                merged.append(hh)
            last = dict(last)
            last["hosts"] = merged
            state.set("last_arp", last)
        state.set("last_default_creds", out)
        db.save_scan("default_creds", out)
        db.push_history("default_creds", f"{out.get('flagged', 0)} appareils signalés")
        if progress:
            progress(100, "OK")
        return out

    if data.get("async", True):
        job = job_manager.submit("default_creds", work)
        return jsonify({"job_id": job.id, "kind": "default_creds"})
    return jsonify(work())


@app.route("/api/wol", methods=["POST"])
def api_wol():
    """Wake-on-LAN magic packet."""
    from modules import wol

    data = request.get_json(force=True, silent=True) or {}
    mac = data.get("mac") or ""
    bcast = data.get("broadcast") or "255.255.255.255"
    result = wol.send_wol(mac, broadcast=bcast, port=int(data.get("port") or 9))
    if result.get("ok"):
        db.push_history("wol", f"WOL {mac}")
    return jsonify(result), (200 if result.get("ok") else 400)


@app.route("/api/host/label", methods=["POST"])
def api_host_label():
    """Custom node label (double-clic topologie L0p4Map)."""
    data = request.get_json(force=True, silent=True) or {}
    key = data.get("key") or data.get("mac") or data.get("ip")
    label = data.get("label")
    if not key:
        return api_response(error="missing_key", status=400)
    result = db.set_host_override(key, label=label if label is not None else "")
    last = state.get("last_arp") or {}
    if last.get("hosts"):
        last = dict(last)
        last["hosts"] = db.apply_overrides_to_hosts(last["hosts"])
        state.set("last_arp", last)
    return jsonify(result)


@app.route("/api/findings", methods=["GET"])
def api_findings_list():
    key = request.args.get("host") or request.args.get("key")
    return jsonify({"findings": db.list_findings(host_key=key, limit=int(request.args.get("limit") or 50))})


@app.route("/api/findings", methods=["POST"])
def api_findings_add():
    data = request.get_json(force=True, silent=True) or {}
    key = data.get("host_key") or data.get("ip") or data.get("mac")
    title = data.get("title") or ""
    if not key or not title:
        return api_response(error="missing_fields", status=400)
    f = db.add_finding(key, title, data.get("detail") or "", data.get("severity") or "info")
    db.push_history("finding", f"{key}: {title}")
    return jsonify(f)


@app.route("/api/host/quick", methods=["POST"])
def api_host_quick():
    """Actions rapides L0p4Map: ping | traceroute | banner | nmap-light."""
    data = request.get_json(force=True, silent=True) or {}
    action = (data.get("action") or "ping").lower()
    target = data.get("ip") or data.get("target")
    if not target:
        return api_response(error="missing_ip", status=400)
    try:
        target = validate_target(target)
    except ValidationError as e:
        return api_response(error=e.code, message=e.message, status=400)
    if action == "ping":
        return jsonify(tools.ping_host(target))
    if action == "traceroute":
        return jsonify(tools.traceroute(target))
    if action == "banner":
        port = int(data.get("port") or 80)
        return jsonify(tools.grab_banner(target, port))
    if action == "nmap-light":
        def work(progress=None):
            if progress:
                progress(10, "nmap -F…")
            # use first available profile or empty custom
            profiles = nmap_scanner.list_profiles()
            prof = "quick" if any(p.get("id") == "quick" for p in profiles) else (
                profiles[0]["id"] if profiles else "default"
            )
            return nmap_scanner.run_scan(target, profile=prof, progress=progress)

        if data.get("async", True):
            job = job_manager.submit("nmap_quick", work)
            return jsonify({"job_id": job.id, "kind": "nmap_quick"})
        return jsonify(work())
    return api_response(error="unknown_action", status=400)


@app.route("/api/intel/summary")
def api_intel_summary():
    """One-shot intelligence pack for UI."""
    from modules.mitre_map import map_network
    from modules import host_scoring, suricata_feed, attack_surface as asurf

    arp = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    nmap = (state.get("last_nmap") or {}).get("hosts", [])
    attack = state.get("last_attack") or asurf.build_attack_surface(arp, nmap)
    mitre = map_network(arp, nmap, attack, state.get("new_devices") or [])
    scores = host_scoring.score_hosts(arp, nmap)
    suri = suricata_feed.read_alerts(limit=15)
    state.set("last_mitre", mitre)
    state.set("last_scores", scores)
    return jsonify(
        {
            "hosts": len(arp),
            "nmap_hosts": len(nmap),
            "mitre": mitre,
            "scores": scores,
            "suricata": suri,
            "snmp": state.get("last_snmp"),
            "wifi": state.get("last_wifi"),
            "lldp": state.get("last_lldp"),
            "netbios": state.get("last_netbios"),
        }
    )


@app.route("/api/host/<path:ip>")
def api_host_detail(ip: str):
    """Aggregate all known data for one host (topologie + drawer)."""
    try:
        ip = validate_target(ip)
    except ValidationError as e:
        return api_response(error=e.code, message=e.message, status=400)

    arp_hosts = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    nmap_hosts = (state.get("last_nmap") or {}).get("hosts", [])
    attack = state.get("last_attack") or {}
    vuln = state.get("last_vuln") or {}

    arp = next((h for h in arp_hosts if h.get("ip") == ip), None)
    nmap = next((h for h in nmap_hosts if h.get("ip") == ip), None)
    atk = next((h for h in attack.get("hosts", []) if h.get("ip") == ip), None)
    vul = next((h for h in vuln.get("hosts", []) if h.get("ip") == ip), None)

    ports = []
    if nmap and nmap.get("ports"):
        ports = [p for p in nmap["ports"] if p.get("state") == "open"]
    elif arp and arp.get("open_ports"):
        ports = [{"port": p, "state": "open", "service": "?"} for p in arp["open_ports"]]

    cves = []
    for s in (vul or {}).get("services") or []:
        cves.extend(s.get("cves") or [])

    return jsonify({
        "ip": ip,
        "arp": arp,
        "nmap": nmap,
        "attack": atk,
        "vuln": vul,
        "ports": ports,
        "exposures": (atk or {}).get("exposures") or [],
        "cves": cves[:30],
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
