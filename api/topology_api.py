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
from modules import attack_surface, network_info, nmap_scanner, tools, topology


bp = Blueprint("topology", __name__)

@bp.route('/api/hosts/<ip>')
def api_host_detail(ip: str):
    try:
        from core import db as _db
        arp = _db.get_last_scan('arp') or {}
        nmap = _db.get_last_scan('nmap') or {}
        # find host in arp or nmap
        host = None
        for h in (arp.get('hosts') or []):
            if h.get('ip') == ip:
                host = h.copy(); break
        if not host:
            for h in (nmap.get('hosts') or []):
                if h.get('ip') == ip:
                    host = h.copy(); break
        if not host:
            # fallback to known_hosts table
            kh = next((k for k in _db.list_known_hosts() if k.get('ip') == ip), None)
            host = kh or {"ip": ip}
        # merge overrides, findings, ports
        host['override'] = _db.get_host_override(host.get('mac') or host.get('ip'))
        host['findings'] = _db.list_findings(host.get('mac') or host.get('ip'))
        # ports from nmap if available
        ports = []
        for h in (nmap.get('hosts') or []):
            if h.get('ip') == ip and h.get('ports'):
                ports = h.get('ports')
                break
        host['ports'] = ports
        # pcap references: none stored, but provide download links if reports exist
        # return host detail
        return jsonify({"ok": True, "host": host})
    except Exception as e:
        log.exception('host detail failed')
        return api_response(error='internal', message=str(e), status=500)
@bp.route("/api/topology")
def api_topology():
    arp_hosts = (state.get("last_arp") or {}).get("hosts", [])
    nmap_hosts = (state.get("last_nmap") or {}).get("hosts", [])
    arp_hosts = db.apply_overrides_to_hosts(arp_hosts)
    graph = topology.build_graph(arp_hosts, nmap_hosts)
    return jsonify(graph)


@bp.route("/api/host/override", methods=["POST"])
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


@bp.route("/api/host/override", methods=["DELETE"])
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


@bp.route("/api/overrides")
def api_overrides():
    return jsonify({"overrides": db.list_overrides()})
@bp.route("/api/host/label", methods=["POST"])
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
@bp.route("/api/host/quick", methods=["POST"])
def api_host_quick():
    """Actions rapides L0p4Map sur un hôte (Attack Surface / Topologie).

    Actions: ping | traceroute | banner | nmap-light | nmap-vuln | port-scan |
             http | tls | dns | dig | whois | ssh-keyscan | port-check | wol
    """
    data = request.get_json(force=True, silent=True) or {}
    action = (data.get("action") or "ping").lower().replace("_", "-")
    target = data.get("ip") or data.get("target")
    if action == "wol":
        from modules import wol

        mac = data.get("mac") or ""
        result = wol.send_wol(mac, broadcast=data.get("broadcast") or "255.255.255.255")
        return jsonify(result), (200 if result.get("ok") else 400)
    if not target:
        return api_response(error="missing_ip", status=400)
    try:
        target = validate_target(target)
    except ValidationError as e:
        return api_response(error=e.code, message=e.message, status=400)

    port = int(data.get("port") or (443 if action == "tls" else 80))

    if action == "ping":
        return jsonify(tools.ping_host(target))
    if action == "traceroute":
        return jsonify(tools.traceroute(target))
    if action == "banner":
        return jsonify(tools.grab_banner(target, port))
    if action == "port-check":
        return jsonify(tools.port_check(target, port))
    if action == "port-scan":
        ports = data.get("ports") or "21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080,8443"
        return jsonify(tools.port_scan(target, str(ports)))
    if action == "http":
        return jsonify(tools.http_probe(target, port=port, https=bool(data.get("https") or port in (443, 8443))))
    if action == "tls":
        return jsonify(tools.tls_inspect(target, port if port != 80 else 443))
    if action == "dns":
        return jsonify(tools.dns_lookup(target))
    if action == "dig":
        return jsonify(tools.dig_records(target))
    if action == "whois":
        return jsonify(tools.whois_lookup(target))
    if action == "ssh-keyscan":
        return jsonify(tools.ssh_keyscan(target, int(data.get("port") or 22)))
    if action in ("nmap-light", "nmap-vuln", "nmap-full"):
        def work(progress=None):
            if progress:
                progress(10, f"{action}…")
            profiles = nmap_scanner.list_profiles()
            ids = {p.get("id") for p in profiles}
            if action == "nmap-vuln":
                prof = "vuln" if "vuln" in ids else ("deep" if "deep" in ids else "quick")
            elif action == "nmap-full":
                prof = "deep" if "deep" in ids else ("full" if "full" in ids else "quick")
            else:
                prof = "quick" if "quick" in ids else (
                    profiles[0]["id"] if profiles else "default"
                )
            return nmap_scanner.run_scan(target, profile=prof, progress=progress)

        if data.get("async", True):
            job = job_manager.submit("nmap_quick", work)
            return jsonify({"job_id": job.id, "kind": "nmap_quick"})
        return jsonify(work())
    return api_response(error="unknown_action", status=400)
@bp.route("/api/host/<path:ip>")
def api_host_data(ip: str):
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
