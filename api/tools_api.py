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
from modules import tools


bp = Blueprint("tools", __name__)

@bp.route("/api/tools/ping", methods=["POST"])
def api_ping():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or data.get("target")
    if not ip:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.ping_host(ip, count=validate_count(data.get("count", 3))))


@bp.route("/api/tools/traceroute", methods=["POST"])
def api_traceroute():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or data.get("target")
    if not ip:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.traceroute(ip, max_hops=validate_count(data.get("max_hops", 20), 20, 1, 64)))


@bp.route("/api/tools/banner", methods=["POST"])
def api_banner():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or data.get("target")
    port = data.get("port", 80)
    if not ip:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.grab_banner(ip, int(port)))


@bp.route("/api/tools/dns", methods=["POST"])
def api_dns():
    data = request.get_json(force=True, silent=True) or {}
    q = data.get("query") or data.get("ip") or data.get("target")
    if not q:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.dns_lookup(q))


@bp.route("/api/tools/tls", methods=["POST"])
def api_tls():
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host") or data.get("ip") or data.get("target")
    port = data.get("port", 443)
    if not host:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.tls_inspect(host, int(port)))


@bp.route("/api/tools/port-check", methods=["POST"])
def api_port_check():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or data.get("target")
    port = data.get("port", 80)
    if not ip:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.port_check(ip, int(port)))


@bp.route("/api/tools/port-scan", methods=["POST"])
def api_port_scan():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or data.get("target")
    ports = data.get("ports") or "21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080"
    if not ip:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.port_scan(ip, str(ports)))


@bp.route("/api/tools/http", methods=["POST"])
def api_http_probe():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("url") or data.get("host") or data.get("ip") or data.get("target")
    if not target:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.http_probe(
        target,
        port=int(data.get("port") or 80),
        path=data.get("path") or "/",
        https=bool(data.get("https")),
    ))


@bp.route("/api/tools/dig", methods=["POST"])
def api_dig():
    data = request.get_json(force=True, silent=True) or {}
    q = data.get("query") or data.get("ip") or data.get("target")
    if not q:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.dig_records(q, data.get("types") or "A,AAAA,MX,NS,TXT,CNAME,SOA"))


@bp.route("/api/tools/whois", methods=["POST"])
def api_whois():
    data = request.get_json(force=True, silent=True) or {}
    q = data.get("query") or data.get("ip") or data.get("target")
    if not q:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.whois_lookup(q))


@bp.route("/api/tools/neighbors", methods=["GET", "POST"])
def api_neighbors():
    return jsonify(tools.neighbors())


@bp.route("/api/tools/routes", methods=["GET", "POST"])
def api_routes():
    return jsonify(tools.routes())


@bp.route("/api/tools/listening", methods=["GET", "POST"])
def api_listening():
    return jsonify(tools.listening_ports())


@bp.route("/api/tools/subnet", methods=["POST"])
def api_subnet():
    data = request.get_json(force=True, silent=True) or {}
    cidr = data.get("cidr") or data.get("target") or data.get("ip")
    if not cidr:
        return api_response(error="missing_cidr", status=400)
    return jsonify(tools.subnet_info(str(cidr)))


@bp.route("/api/tools/mac", methods=["POST"])
def api_mac_lookup():
    data = request.get_json(force=True, silent=True) or {}
    mac = data.get("mac") or data.get("target")
    if not mac:
        return api_response(error="missing_mac", status=400)
    return jsonify(tools.mac_lookup(str(mac)))


@bp.route("/api/tools/ssh-keyscan", methods=["POST"])
def api_ssh_keyscan():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or data.get("target")
    port = data.get("port", 22)
    if not ip:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.ssh_keyscan(ip, int(port)))


@bp.route("/api/tools/mtu", methods=["POST"])
def api_mtu():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or data.get("target")
    size = data.get("size", 1400)
    if not ip:
        return api_response(error="missing_target", status=400)
    return jsonify(tools.mtu_check(ip, int(size)))


@bp.route("/api/tools/catalog", methods=["GET"])
def api_tools_catalog():
    """List available network utilities."""
    return jsonify({
        "ok": True,
        "tools": [
            {"id": "ping", "label": "Ping", "needs": "target"},
            {"id": "traceroute", "label": "Traceroute", "needs": "target"},
            {"id": "banner", "label": "Banner grab", "needs": "target,port"},
            {"id": "dns", "label": "DNS A/AAAA/PTR", "needs": "target"},
            {"id": "dig", "label": "DNS full (dig)", "needs": "target"},
            {"id": "tls", "label": "TLS inspect", "needs": "target,port"},
            {"id": "http", "label": "HTTP probe", "needs": "target"},
            {"id": "port-check", "label": "Port check", "needs": "target,port"},
            {"id": "port-scan", "label": "Port scan light", "needs": "target"},
            {"id": "whois", "label": "WHOIS / RDAP", "needs": "target"},
            {"id": "subnet", "label": "Subnet calc", "needs": "cidr"},
            {"id": "mac", "label": "MAC OUI lookup", "needs": "mac"},
            {"id": "ssh-keyscan", "label": "SSH keyscan", "needs": "target"},
            {"id": "mtu", "label": "MTU path probe", "needs": "target"},
            {"id": "neighbors", "label": "ARP neighbors", "needs": ""},
            {"id": "routes", "label": "Routing table", "needs": ""},
            {"id": "listening", "label": "Local listeners", "needs": ""},
        ],
    })
