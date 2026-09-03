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
from modules import ai_analyst, network_info, remediation


bp = Blueprint("ai", __name__)

@bp.route("/api/ai-analyze")
def api_ai_analyze():
    """Network AI Analyst v3 — works from attack surface and/or last ARP/nmap."""
    attack = state.get("last_attack") or {}
    arp = (state.get("last_arp") or {}).get("hosts") or []
    nmap = (state.get("last_nmap") or {}).get("hosts") or []
    if not attack and not arp and not nmap:
        return api_response(
            error="no_data",
            message="Lancez d'abord un scan ARP et/ou nmap (ou surface d'attaque).",
            status=400,
        )

    intel = {}
    try:
        from modules import host_scoring

        intel = host_scoring.score_hosts(arp, nmap) or {}
    except Exception:
        intel = {}

    snap = state.get("last_network") or {}
    if not snap:
        try:
            snap = network_info.snapshot()
        except Exception:
            snap = {}

    use_ext = request.args.get("external", "1") not in ("0", "false", "False")
    analysis = ai_analyst.analyze_network(
        attack if attack else None,
        intel,
        arp_hosts=arp,
        nmap_hosts=nmap,
        network_snap=snap,
        use_external_ai=use_ext,
    )
    # cache for UI
    try:
        state.set("last_ai", analysis)
    except Exception:
        pass
    try:
        from core import notifications as notifier

        notifier.publish({"type": "ai_analysis", "severity": analysis.get("severity"), "grade": analysis.get("grade")})
    except Exception:
        pass
    try:
        alert_notify(
            f"Network AI {analysis.get('severity')}: grade {analysis.get('grade')} score {analysis.get('risk_score')}",
            source="network-ai",
            severity=analysis.get("severity") or "info",
        )
    except Exception:
        pass
    return jsonify(analysis)


@bp.route("/api/ai-host/<path:ip>")
def api_ai_host(ip: str):
    """Per-host AI briefing."""
    try:
        ip = validate_target(ip)
    except ValidationError as e:
        return api_response(error=e.code, message=e.message, status=400)
    attack = state.get("last_attack") or {}
    host = None
    for h in attack.get("hosts") or []:
        if h.get("ip") == ip:
            host = h
            break
    if not host:
        arp = (state.get("last_arp") or {}).get("hosts") or []
        nmap = (state.get("last_nmap") or {}).get("hosts") or []
        host = next((h for h in arp if h.get("ip") == ip), None) or next(
            (h for h in nmap if h.get("ip") == ip), None
        )
    if not host:
        return api_response(error="not_found", message="Hôte inconnu dans la session.", status=404)
    return jsonify(ai_analyst.analyze_host(ip, host, attack))


@bp.route("/api/ai-last")
def api_ai_last():
    last = state.get("last_ai")
    if not last:
        return api_response(error="no_data", message="Aucune analyse AI en cache.", status=404)
    return jsonify(last)


@bp.route("/api/remediation/script/<ip>", methods=["GET"])
def api_remediation_script(ip: str):
    attack = state.get("last_attack")
    if not attack:
        return api_response(error="no_data", message="Données d'attaque introuvables.")

    host = next((h for h in attack.get("hosts", []) if h["ip"] == ip), None)
    if not host:
        return api_response(error="not_found", message="Hôte non trouvé dans la surface d'attaque.")

    script = remediation.generate_bash_script(ip, host.get("exposures", []))
    return Response(
        script,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment;filename=hardening_{ip}.sh"},
    )
