"""
HARMATTAN — Feature API: endpoints for the intel / decoy / IoT / notifier / aux modules.

Exposes the new modules added to the suite:
  * /api/intel/adversaries      — intel_gatherer.correlate()
  * /api/honeypot               — honeypot_lite start/stop/status
  * /api/iot/enumerate          — iot_enumerator.enumerate_hosts()
  * /api/notifier               — traffic_notifier start/stop/status
  * /api/dns/enumerate          — dns_enum.enumerate_subdomains()
  * /api/tls/analyze            — tls_analyzer.scan_hosts() / inspect_host()
  * /api/ports/trends           — port_trends.record()/trends()
  * /api/netflow/export         — netflow_export.export_packets()

All endpoints follow the suite conventions (validate + optional job + api_response).
"""
from __future__ import annotations

import time

from flask import Blueprint, jsonify, request

from api.deps import db, job_manager, log, state, api_response
from core.validation import ValidationError, validate_target
from core.alerts import notify as alert_notify

bp = Blueprint("features", __name__)


def _validated_target_or_err():
    """Parse+validate a target/domain from JSON body; return (target, None) or (None, resp)."""
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target") or data.get("ip") or data.get("domain")
    if not target:
        return None, api_response(error="missing_target",
                                  message="Champ requis: target / ip / domain.", status=400)
    try:
        target = validate_target(target)
    except ValidationError as e:
        return None, api_response(error=e.code, message=e.message, status=400)
    return target, None


# --------------------------------------------------------------------------- intel
@bp.route("/api/intel/adversaries", methods=["POST"])
def api_intel_adversaries():
    from modules import intel_gatherer, mitre_map

    data = request.get_json(force=True, silent=True) or {}
    # Build a mapping from current state (last_arp / last_nmap) unless a mapping is passed
    if data.get("mapping"):
        mapping = data["mapping"]
    else:
        arp = (state.get("last_arp") or {}).get("hosts", [])
        nmap = (state.get("last_nmap") or {}).get("hosts", [])
        attack = state.get("last_attack") or {}
        mapping = mitre_map.map_network(arp_hosts=arp, nmap_hosts=nmap, attack=attack)

    corr = intel_gatherer.correlate(mapping)
    corr["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    db.push_history("intel", intel_gatherer.summarize(corr))
    state.set("last_intel", corr)
    return api_response(data=corr)


# ----------------------------------------------------------------------- honeypot
@bp.route("/api/honeypot", methods=["GET"])
def api_honeypot_status():
    from modules import honeypot_lite
    return api_response(data=honeypot_lite.status())


@bp.route("/api/honeypot", methods=["POST"])
def api_honeypot_start():
    from modules import honeypot_lite
    data = request.get_json(force=True, silent=True) or {}
    bind = data.get("bind") or "0.0.0.0"
    ports = data.get("ports")
    ok, msg = honeypot_lite.start(bind=bind, ports=ports)
    return api_response(data=honeypot_lite.status(), message=msg, status=200 if ok else 400)


@bp.route("/api/honeypot", methods=["DELETE"])
def api_honeypot_stop():
    from modules import honeypot_lite
    ok, msg = honeypot_lite.stop()
    return api_response(data=honeypot_lite.status(), message=msg, status=200 if ok else 400)


# --------------------------------------------------------------------------- iot
@bp.route("/api/iot/enumerate", methods=["POST"])
def api_iot_enumerate():
    from modules import iot_enumerator

    hosts = (request.get_json(force=True, silent=True) or {}).get("hosts")
    if not hosts:
        hosts = (state.get("last_arp") or {}).get("hosts", [])
    if not hosts:
        return api_response(error="no_hosts", message="Lance un scan ARP d'abord, ou passe `hosts`.", status=400)

    result = iot_enumerator.enumerate_hosts(hosts)
    result["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    db.push_history("iot", iot_enumerator.summarize(result))
    state.set("last_iot", result)
    return api_response(data=result)


# ----------------------------------------------------------------------- notifier
@bp.route("/api/notifier", methods=["GET"])
def api_notifier_status():
    from modules import traffic_notifier
    return api_response(data=traffic_notifier.status())


@bp.route("/api/notifier", methods=["POST"])
def api_notifier_start():
    from modules import traffic_notifier
    data = request.get_json(force=True, silent=True) or {}
    interval = int(data.get("interval") or 15)
    ok, msg = traffic_notifier.start(interval=interval)
    return api_response(data=traffic_notifier.status(), message=msg, status=200 if ok else 400)


@bp.route("/api/notifier", methods=["DELETE"])
def api_notifier_stop():
    from modules import traffic_notifier
    ok, msg = traffic_notifier.stop()
    return api_response(data=traffic_notifier.status(), message=msg, status=200 if ok else 400)


# --------------------------------------------------------------------------- dns
@bp.route("/api/dns/enumerate", methods=["POST"])
def api_dns_enumerate():
    from modules import dns_enum

    data = request.get_json(force=True, silent=True) or {}
    domain = data.get("domain") or data.get("target")
    if not domain:
        return api_response(error="missing_domain", message="Champ requis: domain.", status=400)
    words = data.get("words")
    max_threads = int(data.get("max_threads") or 40)

    def work(progress=None):
        if progress:
            progress(5, f"DNS enum {domain}…")
        result = dns_enum.enumerate_subdomains(domain, words=words, max_threads=max_threads)
        result["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        db.push_history("dns", dns_enum.summarize(result))
        state.set("last_dns", result)
        if progress:
            progress(100, "OK")
        return result

    if data.get("async"):
        job = job_manager.submit("dns-enum", work)
        return jsonify({"job_id": job.id, "kind": "dns-enum"})
    return api_response(data=work())


# ---------------------------------------------------------------------------- tls
@bp.route("/api/tls/analyze", methods=["POST"])
def api_tls_analyze():
    from modules import tls_analyzer

    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target") or data.get("ip")
    if target:
        try:
            target = validate_target(target)
        except ValidationError as e:
            return api_response(error=e.code, message=e.message, status=400)
        result = tls_analyzer.inspect_host(target, port=int(data.get("port") or 443))
        state.set("last_tls", result)
        return api_response(data=result)

    hosts = data.get("hosts") or (state.get("last_arp") or {}).get("hosts", [])
    if not hosts:
        return api_response(error="no_hosts", message="Passe target/ip ou hosts (ou scan ARP).", status=400)
    result = tls_analyzer.scan_hosts(hosts, ports=data.get("ports"),
                                     max_hosts=int(data.get("max") or 40))
    result["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    db.push_history("tls", tls_analyzer.summarize(result))
    state.set("last_tls", result)
    return api_response(data=result)


# ------------------------------------------------------------------- port trends
@bp.route("/api/ports/trends", methods=["GET", "POST"])
def api_port_trends():
    from modules import port_trends

    if request.method == "POST":
        hosts = (request.get_json(force=True, silent=True) or {}).get("hosts")
        if not hosts:
            hosts = (state.get("last_arp") or {}).get("hosts", [])
        result = port_trends.record(hosts or [])
    else:
        result = port_trends.trends()
    result["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    db.push_history("ports", f"Port-trends: {result.get('hosts_with_new_ports', result.get('count', 0))} hôte(s) évoluent")
    return api_response(data=result)


# ------------------------------------------------------------------------ netflow
@bp.route("/api/netflow/export", methods=["POST"])
def api_netflow_export():
    from modules import netflow_export

    data = request.get_json(force=True, silent=True) or {}
    packets = data.get("packets")
    if not packets:
        # fallback: export whatever is in the last traffic snapshot
        snap = state.get("last_traffic") or {}
        packets = snap.get("packets") or snap.get("items") or []
    if not packets:
        return api_response(error="no_packets", message="Passe `packets` ou lance une capture d'abord.", status=400)

    result = netflow_export.export_packets(
        packets,
        collector_host=data.get("collector_host") or "127.0.0.1",
        collector_port=int(data.get("collector_port") or 9996),
        source_id=int(data.get("source_id") or 1),
    )
    db.push_history("netflow", netflow_export.summarize(result))
    return api_response(data=result)
