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
from core.auth import login_required
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
from modules import arp_scanner, network_info, nmap_scanner

import time as _time
_STARTED_AT = _time.time()

def _fmt_uptime(seconds: float) -> str:
    d = int(seconds // 86400)
    h = int((seconds % 86400) // 3600)
    m = int((seconds % 3600) // 60)
    if d > 0:
        return f"{d}j {h}h {m}m"
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m"


bp = Blueprint("system", __name__)

@bp.route("/")
@login_required
def index():
    user = None
    try:
        from core.auth import current_user
        user = current_user()
    except Exception:
        user = None
    snap = network_info.snapshot()
    state.set("last_network", snap)
    db.save_scan("network", snap)
    actor = None
    if user:
        actor = {"username": user.get("username"), "role": user.get("role")}
    return render_template(
        "index.html",
        default_subnet=snap.get("subnet") or network_info.get_local_subnet(),
        version=VERSION,
        token=get_runtime_token() or "",
        user=actor,
    )
@bp.route("/api/health")
def api_health():
    """
    Structured health check: python/nmap/scapy/root, DB rw test, disk space,
    memory, service uptime and last scan timestamp. Public endpoint.
    """
    import platform
    import shutil
    import sys
    import time as _time

    from modules import monitor as mon

    checks = []
    healthy = True

    def add(name, ok, detail=None):
        nonlocal healthy
        if not ok:
            healthy = False
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    # --- Runtime / binaries ---
    add(
        "python",
        sys.version_info >= (3, 10),
        f"Python {platform.python_version()}",
    )
    nmap_ok = bool(
        shutil.which("nmap") or (hasattr(nmap_scanner, "nmap_available") and nmap_scanner.nmap_available())
    )
    add("nmap", nmap_ok, "nmap binaire disponible" if nmap_ok else "nmap introuvable")
    add("scapy", bool(getattr(arp_scanner, "SCAPY_AVAILABLE", False)), "scapy importé")
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    add("root", is_root, "running as root" if is_root else "non-root (CAP_NET_RAW requis pour capture)")
    # non-root is an env note, not a service failure — exclude it from overall health
    healthy = all(c["ok"] or c["name"] == "root" for c in checks)

    # --- DB read/write test ---
    db_ok = True
    db_detail = "ok"
    try:
        with db.db_cursor() as cur:
            cur.execute("SELECT 1")
            cur.rowcount
        if db_ok:
            db_detail = "lecture ok"
    except Exception as e:
        db_ok = False
        db_detail = f"Échec: {e}"
    add("db", db_ok, db_detail)

    # --- Disk space on DATA_DIR ---
    disk = {}
    try:
        disk_usage = shutil.disk_usage(str(REPORTS_DIR))
        free_gb = disk_usage.free / (1024 ** 3)
        disk = {
            "free_gb": round(free_gb, 2),
            "total_gb": round(disk_usage.total / (1024 ** 3), 2),
        }
        add("disk", free_gb > 0.5, f"{round(free_gb,2)} Go libres")
    except Exception as e:
        add("disk", False, f"Erreur: {e}")

    # --- Memory (psutil) ---
    mem = {}
    mem_ok = True
    try:
        import psutil

        vm = psutil.virtual_memory()
        mem = {
            "total_mb": round(vm.total / (1024 ** 2), 1),
            "avail_mb": round(vm.available / (1024 ** 2), 1),
            "percent": vm.percent,
        }
        add("memory", vm.percent < 95, f"{vm.percent}% utilisé")
    except Exception:
        mem_ok = False
        add("memory", False, "psutil indisponible")
    if mem_ok and mem:
        mem_ok = mem.get("percent", 0) < 95

    # --- Service uptime ---
    try:
        uptime_s = _time.time() - _STARTED_AT
        add("uptime", True, _fmt_uptime(uptime_s))
    except Exception:
        add("uptime", True, "n/a")

    # --- Last scan timestamp ---
    last_scan = None
    try:
        last = db.get_last_scan(None)
        if last:
            last_scan = last.get("created")
            add("last_scan", True, last_scan)
        else:
            add("last_scan", True, "aucun scan enregistré")
    except Exception as e:
        add("last_scan", False, f"Erreur: {e}")

    mon_st = {}
    try:
        mon_st = mon.status()
    except Exception:
        mon_st = {"running": False}

    resp = jsonify({
        "ok": healthy,
        "status": "healthy" if healthy else "degraded",
        "version": VERSION,
        "time": datetime.now().isoformat(timespec="seconds"),
        "uptime": _fmt_uptime(_time.time() - _STARTED_AT),
        "auth_enabled": bool(get_runtime_token()),
        "checks": checks,
        "runtime": {
            "python": platform.python_version(),
            "nmap": nmap_ok,
            "scapy": bool(getattr(arp_scanner, "SCAPY_AVAILABLE", False)),
            "root": is_root,
        },
        "db": {"ok": db_ok, "path": str(REPORTS_DIR)},
        "disk": disk,
        "memory": mem,
        "last_scan": last_scan,
        "scapy": arp_scanner.SCAPY_AVAILABLE,
        "nmap": nmap_ok,
        "jobs_running": sum(
            1 for j in (job_manager.list_jobs() or [])
            if (j.get("status") if isinstance(j, dict) else getattr(j, "status", None)) in ("running", "pending", "queued")
        ),
        "monitor": mon_st,
        "has_arp": bool((state.get("last_arp") or {}).get("hosts")),
        "has_nmap": bool((state.get("last_nmap") or {}).get("hosts")),
        "known_hosts": len(db.list_known_hosts()),
        "overrides": len(db.list_overrides()),
        "preflight": state.get("preflight", {}),
    })
    resp.status_code = 200  # service alive → 200 always; status field carries health
    return resp


@bp.route("/api/preflight")
def api_preflight():
    """Return environment checks collected at startup."""
    return jsonify(state.get("preflight", {}))


@bp.route("/api/shutdown", methods=["POST", "GET"])
def api_shutdown():
    """Graceful shutdown of the server (used by desktop app)."""
    import threading

    log.info("Shutdown requested via /api/shutdown")

    def _delayed_exit():
        import signal
        import time

        time.sleep(0.5)
        os.kill(os.getpid(), signal.SIGTERM)

    threading.Thread(target=_delayed_exit, daemon=True).start()
    return api_response({"shutdown": True})


@bp.route('/api/stream')
def api_stream():
    """SSE stream for live UI updates. Auth via header, cookie, or (if enabled) query token."""
    from core.auth import check_request_auth, get_runtime_token

    if get_runtime_token():
        ok, _info = check_request_auth(request)
        if not ok:
            return api_response(error='unauthorized', message='Token requis pour le stream.', status=401)

    def event_stream():
        q = None
        try:
            from core import notifications as notifier
            q = notifier.subscribe()
            while True:
                try:
                    ev = q.get(timeout=25)
                    import json as _json
                    ev_type = ev.get('type', 'message')
                    payload = _json.dumps(ev)
                    yield f"event: {ev_type}\ndata: {payload}\n\n"
                except queue.Empty:
                    yield ':\n'
                except GeneratorExit:
                    break
        finally:
            if q is not None:
                try:
                    notifier.unsubscribe(q)
                except Exception:
                    pass

    return Response(event_stream(), mimetype='text/event-stream')


@bp.route("/api/metrics")
def api_metrics():
    """JSON + Prometheus text metrics (public for local monitoring)."""
    from core.metrics import metrics

    if request.args.get("format") == "prometheus" or (
        "text/plain" in (request.headers.get("Accept") or "")
    ):
        return Response(metrics.prometheus(), mimetype="text/plain; version=0.0.4")
    snap = metrics.snapshot()
    snap["ok"] = True
    snap["version"] = VERSION
    snap["jobs"] = job_manager.list_jobs(limit=10)
    return jsonify(snap)



@bp.route("/api/ready")
def api_ready_alias():
    """Suite-compatible ready (public, no token)."""
    try:
        from pathlib import Path as _P
        mem = {}
        for ln in _P("/proc/meminfo").read_text().splitlines():
            if ln.startswith("MemAvailable") or ln.startswith("MemTotal"):
                k, v = ln.split(":", 1)
                mem[k] = int(v.split()[0])
        mem_info = {
            "mem_total_kb": mem.get("MemTotal"),
            "mem_avail_kb": mem.get("MemAvailable"),
            "mem_avail_mb": round((mem.get("MemAvailable") or 0) / 1024, 1),
        }
    except Exception:
        mem_info = {}
    return jsonify({
        "ok": True,
        "app": "harmattan",
        "version": VERSION,
        "ready": True,
        "auth_enabled": bool(get_runtime_token()),
        "scapy": arp_scanner.SCAPY_AVAILABLE,
        "nmap": nmap_scanner.nmap_available(),
        **mem_info,
    })


@bp.route("/api/system-check")
@bp.route("/api/status")
def api_system_check():
    snap = network_info.snapshot()
    resp = jsonify({
        "scapy": arp_scanner.SCAPY_AVAILABLE,
        "nmap": nmap_scanner.nmap_available(),
        "local_subnet": snap.get("subnet"),
        "local_ip": snap.get("local_ip"),
        "gateway": snap.get("gateway"),
        "ssid": snap.get("ssid"),
        "interfaces": snap.get("interfaces", []),
        "running_as_root": snap.get("running_as_root"),
        "version": VERSION,
        "auth_enabled": bool(get_runtime_token()),
    })
    # publish system-check for UI
    try:
        from core import notifications as notifier
        notifier.publish({"type": "system", "system": snap})
    except Exception:
        pass
    return resp


@bp.route("/api/network-info")
def api_network_info():
    iface = validate_iface(request.args.get("iface") or None)
    snap = network_info.snapshot(iface)
    state.set("last_network", snap)
    return jsonify(snap)


@bp.route("/api/interfaces")
def api_interfaces():
    return jsonify({"interfaces": network_info.get_interfaces()})


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------
@bp.route("/api/jobs")
def api_jobs_list():
    return jsonify({"jobs": job_manager.list_jobs()})


@bp.route("/api/jobs/<job_id>")
def api_job_get(job_id: str):
    job = job_manager.get(job_id)
    if not job:
        return api_response(error="not_found", message="Job introuvable.", status=404)
    return jsonify(job.to_dict(include_result=True))


@bp.route("/api/jobs/<job_id>/cancel", methods=["POST"])
def api_job_cancel(job_id: str):
    if job_manager.cancel(job_id):
        return jsonify({"ok": True, "message": "Annulation demandée."})
    return api_response(error="not_found", message="Job introuvable.", status=404)


# ---------------------------------------------------------------------------
# Notifications / Alerts endpoints
# ---------------------------------------------------------------------------

@bp.route('/api/notifications')
def api_notifications():
    """List recent notifications (from DB)."""
    try:
        from core import db as _db
        nots = _db.list_notifications()
        return jsonify({"ok": True, "notifications": nots})
    except Exception as e:
        log.exception('Failed listing notifications')
        return api_response(error='internal', message=str(e), status=500)


@bp.route('/api/alerts/rules', methods=['GET', 'POST'])
def api_alert_rules():
    from core import db as _db
    if request.method == 'GET':
        try:
            return jsonify({"ok": True, "rules": _db.list_alert_rules()})
        except Exception as e:
            log.exception('alert rules list failed')
            return api_response(error='internal', message=str(e), status=500)
    data = request.get_json(force=True, silent=True) or {}
    name = data.get('name') or data.get('title') or 'rule'
    event_type = data.get('event_type') or data.get('type') or 'message'
    condition = data.get('condition')
    webhook = data.get('webhook')
    try:
        rule = _db.add_alert_rule(name, event_type, condition, webhook)
        return jsonify({"ok": True, "rule": rule})
    except Exception as e:
        log.exception('add alert rule failed')
        return api_response(error='internal', message=str(e), status=500)

@bp.route("/api/settings", methods=["GET"])
def api_settings_get():
    return jsonify({
        "sahel_url": db.get_setting("sahel_url", os.environ.get("SAHEL_URL", "http://127.0.0.1:8099")),
        "theme": db.get_setting("theme", "dark"),
    })


@bp.route("/api/settings", methods=["POST"])
def api_settings_set():
    data = request.get_json(force=True, silent=True) or {}
    for k in ("sahel_url", "theme"):
        if k in data and data[k] is not None:
            db.set_setting(k, str(data[k]))
    return api_response(message="Paramètres enregistrés", data={
        "sahel_url": db.get_setting("sahel_url", ""),
        "theme": db.get_setting("theme", "dark"),
    })


@bp.route("/api/scans")
def api_scans_list():
    kind = request.args.get("kind")
    return jsonify({"scans": db.list_scans(kind=kind, limit=int(request.args.get("limit") or 40))})


@bp.route("/api/scans/<int:scan_id>")
def api_scan_get(scan_id: int):
    s = db.get_scan(scan_id)
    if not s:
        return api_response(error="not_found", status=404)
    return jsonify(s)


@bp.route("/api/scans/<int:scan_id>/load", methods=["POST"])
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
@bp.route("/api/history")
def api_history():
    return jsonify({"history": db.get_history(40)})


@bp.route("/api/history", methods=["DELETE"])
@bp.route("/api/history/clear", methods=["POST"])
def api_history_clear():
    n = db.clear_history()
    db.push_history("cleanup", f"Journal vidé ({n} entrées)")
    return api_response(message=f"{n} entrées journal supprimées", data={"deleted": n})


@bp.route("/api/known-hosts")
def api_known_hosts():
    return jsonify({"hosts": db.list_known_hosts(), "new_devices": state.get("new_devices") or []})


@bp.route("/api/known-hosts/<path:mac>", methods=["DELETE"])
def api_known_host_delete(mac: str):
    ok = db.delete_known_host(mac)
    if ok:
        db.push_history("cleanup", f"Hôte connu supprimé: {mac}")
    return api_response(
        message="Hôte connu supprimé" if ok else "Introuvable",
        data={"deleted": ok, "mac": mac},
        status=200 if ok else 404,
    )


@bp.route("/api/known-hosts", methods=["DELETE"])
@bp.route("/api/known-hosts/clear", methods=["POST"])
def api_known_hosts_clear():
    n = db.clear_known_hosts()
    state.set("new_devices", [])
    db.push_history("cleanup", f"Tous les hôtes connus vidés ({n})")
    return api_response(message=f"{n} hôtes connus supprimés", data={"deleted": n})


@bp.route("/api/ignored-hosts")
def api_ignored_hosts_list():
    return jsonify({"ignored": db.list_ignored_hosts()})


@bp.route("/api/ignored-hosts", methods=["POST"])
def api_ignored_hosts_add():
    data = request.get_json(force=True, silent=True) or {}
    key = data.get("key") or data.get("mac") or data.get("ip") or ""
    reason = data.get("reason") or ""
    if not key:
        return api_response(error="missing_key", message="MAC ou IP requis.", status=400)
    entry = db.add_ignored_host(key, reason)
    # Also remove from known + current session ARP
    mac = (data.get("mac") or key if ":" in key else "").upper()
    ip = data.get("ip") or (key if ":" not in key else "")
    if mac:
        db.delete_known_host(mac)
    _purge_host_from_session(mac=mac or None, ip=ip or None)
    db.push_history("ignore", f"Ignoré: {entry['key']}")
    return jsonify({"ok": True, "ignored": entry})


@bp.route("/api/ignored-hosts/<path:key>", methods=["DELETE"])
def api_ignored_hosts_remove(key: str):
    ok = db.remove_ignored_host(key)
    return api_response(
        message="Retiré de la liste ignorés" if ok else "Introuvable",
        data={"deleted": ok},
        status=200 if ok else 404,
    )


@bp.route("/api/ignored-hosts", methods=["DELETE"])
@bp.route("/api/ignored-hosts/clear", methods=["POST"])
def api_ignored_hosts_clear():
    n = db.clear_ignored_hosts()
    return api_response(message=f"{n} entrées ignorées vidées", data={"deleted": n})


@bp.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def api_scan_delete(scan_id: int):
    ok = db.delete_scan(scan_id)
    if ok:
        db.push_history("cleanup", f"Scan #{scan_id} supprimé")
    return api_response(
        message="Scan supprimé" if ok else "Introuvable",
        data={"deleted": ok},
        status=200 if ok else 404,
    )


@bp.route("/api/scans", methods=["DELETE"])
@bp.route("/api/scans/clear", methods=["POST"])
def api_scans_clear():
    data = request.get_json(force=True, silent=True) or {}
    kind = data.get("kind") or request.args.get("kind") or None
    n = db.clear_scans(kind)
    db.push_history("cleanup", f"Scans vidés ({n})" + (f" kind={kind}" if kind else ""))
    return api_response(message=f"{n} scans supprimés", data={"deleted": n, "kind": kind})


@bp.route("/api/findings/<int:finding_id>", methods=["DELETE"])
def api_finding_delete(finding_id: int):
    ok = db.delete_finding(finding_id)
    return api_response(
        message="Finding supprimé" if ok else "Introuvable",
        data={"deleted": ok},
        status=200 if ok else 404,
    )


@bp.route("/api/findings", methods=["DELETE"])
@bp.route("/api/findings/clear", methods=["POST"])
def api_findings_clear():
    data = request.get_json(force=True, silent=True) or {}
    host_key = data.get("host") or data.get("host_key")
    n = db.clear_findings(host_key)
    return api_response(message=f"{n} findings supprimés", data={"deleted": n})


def _purge_host_from_session(*, mac: str | None = None, ip: str | None = None) -> dict:
    """Remove a host from in-memory ARP / attack / nmap session state."""
    removed = {"arp": False, "attack": False, "nmap": False}
    mac_u = (mac or "").upper()
    ip_s = (ip or "").strip()

    def _keep(h: dict) -> bool:
        if mac_u and (h.get("mac") or "").upper() == mac_u:
            return False
        if ip_s and (h.get("ip") or "").strip() == ip_s:
            return False
        return True

    last = state.get("last_arp")
    if isinstance(last, dict) and last.get("hosts"):
        hosts = [h for h in last["hosts"] if _keep(h)]
        if len(hosts) != len(last["hosts"]):
            last = dict(last)
            last["hosts"] = hosts
            last["count"] = len(hosts)
            state.set("last_arp", last)
            removed["arp"] = True

    atk = state.get("last_attack")
    if isinstance(atk, dict) and atk.get("hosts"):
        hosts = [h for h in atk["hosts"] if _keep(h)]
        if len(hosts) != len(atk["hosts"]):
            atk = dict(atk)
            atk["hosts"] = hosts
            state.set("last_attack", atk)
            removed["attack"] = True

    nmap = state.get("last_nmap")
    if isinstance(nmap, dict) and nmap.get("hosts"):
        hosts = [h for h in nmap["hosts"] if _keep(h)]
        if len(hosts) != len(nmap["hosts"]):
            nmap = dict(nmap)
            nmap["hosts"] = hosts
            state.set("last_nmap", nmap)
            removed["nmap"] = True

    return removed


@bp.route("/api/session/host", methods=["DELETE"])
def api_session_host_remove():
    """Remove one host from current session (and optionally known + ignore)."""
    data = request.get_json(force=True, silent=True) or {}
    mac = (data.get("mac") or "").strip()
    ip = (data.get("ip") or "").strip()
    if not mac and not ip:
        return api_response(error="missing_key", message="ip ou mac requis.", status=400)
    removed = _purge_host_from_session(mac=mac or None, ip=ip or None)
    known_del = False
    if mac:
        known_del = db.delete_known_host(mac)
    if data.get("forget_known") and not known_del and mac:
        known_del = db.delete_known_host(mac)
    ignored = None
    if data.get("ignore"):
        key = mac or ip
        ignored = db.add_ignored_host(key, data.get("reason") or "manual")
    db.push_history("cleanup", f"Session − {ip or mac}")
    return jsonify({
        "ok": True,
        "removed": removed,
        "known_deleted": known_del,
        "ignored": ignored,
    })


@bp.route("/api/session/clear", methods=["POST"])
def api_session_clear():
    """Clear in-memory scan session (ARP/nmap/attack/vuln) without wiping DB."""
    data = request.get_json(force=True, silent=True) or {}
    keys = data.get("keys") or ["last_arp", "last_nmap", "last_vuln", "last_attack", "last_topology", "new_devices", "prev_arp"]
    cleared = []
    for k in keys:
        state.set(k, None if k != "new_devices" else [])
        cleared.append(k)
    db.push_history("cleanup", f"Session vidée: {', '.join(cleared)}")
    return api_response(message="Session runtime vidée", data={"cleared": cleared})


@bp.route("/api/session/export")
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
