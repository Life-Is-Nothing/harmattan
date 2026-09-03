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
from modules import network_info


bp = Blueprint("intel", __name__)

@bp.route("/api/snmp/probe", methods=["POST"])
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


@bp.route("/api/netbios/probe", methods=["POST"])
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


@bp.route("/api/lldp-cdp", methods=["POST"])
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


@bp.route("/api/wifi/scan", methods=["POST"])
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
@bp.route("/api/mitre")
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


@bp.route("/api/score/hosts", methods=["POST", "GET"])
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


@bp.route("/api/suricata/alerts")
def api_suricata_alerts():
    from modules import suricata_feed

    path = request.args.get("path")
    limit = int(request.args.get("limit") or 50)
    return jsonify(suricata_feed.read_alerts(path=path, limit=limit))
@bp.route("/api/range-map", methods=["POST"])
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


@bp.route("/api/default-creds", methods=["POST"])
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


@bp.route("/api/wol", methods=["POST"])
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
@bp.route("/api/findings", methods=["GET"])
def api_findings_list():
    key = request.args.get("host") or request.args.get("key")
    return jsonify({"findings": db.list_findings(host_key=key, limit=int(request.args.get("limit") or 50))})


@bp.route("/api/findings", methods=["POST"])
def api_findings_add():
    data = request.get_json(force=True, silent=True) or {}
    key = data.get("host_key") or data.get("ip") or data.get("mac")
    title = data.get("title") or ""
    if not key or not title:
        return api_response(error="missing_fields", status=400)
    f = db.add_finding(key, title, data.get("detail") or "", data.get("severity") or "info")
    db.push_history("finding", f"{key}: {title}")
    return jsonify(f)
@bp.route("/api/ipv6/scan")
def api_ipv6_scan():
    from modules import ipv6_discovery
    iface = request.args.get("iface")
    return jsonify(ipv6_discovery.ipv6_scan(iface=iface))


@bp.route("/api/ot/scan")
def api_ot_scan():
    from modules import ot_probes
    hosts = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    if not hosts:
        return api_response(error="no_hosts", message="Lancer un scan ARP d'abord.")
    return jsonify(ot_probes.scan_hosts(hosts))


@bp.route("/api/creds/active", methods=["POST"])
def api_creds_active():
    from modules import default_creds
    data = request.json or {}
    hosts = data.get("hosts")
    if not hosts:
        hosts = db.apply_overrides_to_hosts((state.get("last_arp") or {}).get("hosts", []))
    
    # Run deep+active scan
    res = default_creds.scan_hosts(hosts, active=True, deep=True)
    state.set("last_active_creds", res)
    return jsonify(res)


@bp.route("/api/intel/summary")
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
            "ot": state.get("last_ot"),
            "ipv6": state.get("last_ipv6"),
        }
    )
