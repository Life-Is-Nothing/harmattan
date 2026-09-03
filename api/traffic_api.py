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
from modules import network_info, sahel_correlate
from modules.traffic_analyzer import TrafficCapture


bp = Blueprint("traffic", __name__)

@bp.route("/api/traffic/start", methods=["POST"])
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


@bp.route("/api/traffic/oneshot", methods=["POST"])
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


@bp.route("/api/traffic/stop", methods=["POST"])
def api_traffic_stop():
    cap = state.capture
    if cap:
        cap.stop()
    db.push_history("traffic", "Capture arrêtée")
    return jsonify({"message": "Capture arrêtée."})


@bp.route("/api/traffic/packets")
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


@bp.route("/api/traffic/packet/<int:no>")
def api_traffic_packet_detail(no: int):
    """Détail d'un paquet : layers + hex dump."""
    cap = state.capture
    if not cap:
        return api_response(error="no_capture", status=404)
    p = cap.get_packet(no)
    if not p:
        return api_response(error="not_found", message=f"Paquet #{no} introuvable", status=404)
    return jsonify(p)


@bp.route("/api/traffic/follow/<int:no>")
def api_traffic_follow(no: int):
    """Follow TCP/UDP stream (Wireshark)."""
    cap = state.capture
    if not cap:
        return api_response(error="no_capture", status=404)
    result = cap.follow_stream(no)
    status = 200 if result.get("ok") else 400
    return jsonify(result), status


@bp.route("/api/traffic/follow/<int:no>/export.txt")
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


@bp.route("/api/traffic/follow/<int:no>/export.json")
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


@bp.route("/api/sahel/correlate", methods=["POST"])
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


@bp.route("/api/sahel/correlate/last")
def api_sahel_correlate_last():
    return jsonify(state.get("last_correlation") or {"ok": False, "message": "aucune corrélation"})


@bp.route("/api/traffic/clear", methods=["POST"])
def api_traffic_clear():
    cap = state.capture
    if not cap:
        return api_response(message="Rien à vider", data={"cleared": False})
    snap = cap.clear()
    db.push_history("traffic", "Buffer trafic vidé")
    return api_response(message="Buffer vidé", data=snap)


@bp.route("/api/traffic/proto-stats")
def api_traffic_proto_stats():
    cap = state.capture
    if not cap:
        return jsonify({"protocols": [], "unique": 0})
    return jsonify(cap.protocol_stats())


@bp.route("/api/traffic/snapshot")
def api_traffic_snapshot():
    cap = state.capture
    if not cap:
        return jsonify({
            "running": False, "error": None, "total_packets": 0,
            "recent_packets": [], "top_flows": [], "bytes_total": 0,
        })
    return jsonify(cap.snapshot())


@bp.route("/api/traffic/export.csv")
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


@bp.route("/api/traffic/export.pcap")
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


@bp.route("/api/traffic/import.pcap", methods=["POST"])
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
