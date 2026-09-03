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
from modules import arp_scanner, attack_surface, network_info, nmap_scanner, topology, vuln_scanner
from modules.diff_scan import diff_arp
from modules.mdns_discovery import discover_mdns_ssdp


bp = Blueprint("scan", __name__)

def _do_arp_scan(subnet, iface, enrich, light, progress=None):
    prev = state.get("last_arp")
    result = arp_scanner.arp_scan(
        subnet, iface=iface, enrich=enrich, light=light, progress=progress
    )
    # publish arp result to live UI if available
    try:
        from core import notifications as notifier
        notifier.publish({"type": "arp.update", "result": result})
    except Exception:
        pass
    if not result.get("error"):
        hosts = db.filter_ignored_hosts(result.get("hosts") or [])
        raw_count = len(result.get("hosts") or [])
        result = dict(result)
        result["hosts"] = hosts
        result["count"] = len(hosts)
        result["ignored_filtered"] = max(0, raw_count - len(hosts))
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


@bp.route("/api/arp-scan", methods=["POST"])
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
    if not arp.get("error"):
        hosts = db.filter_ignored_hosts(arp.get("hosts") or [])
        arp = dict(arp)
        arp["hosts"] = hosts
        arp["count"] = len(hosts)
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


@bp.route("/api/home-scan", methods=["POST"])
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


@bp.route("/api/nmap-scan", methods=["POST"])
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


@bp.route("/api/nmap-profiles")
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


@bp.route("/api/vuln-scan", methods=["POST"])
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
@bp.route("/api/attack-surface")
def api_attack_surface():
    attack = attack_surface.build_attack_surface(
        (state.get("last_arp") or {}).get("hosts", []),
        (state.get("last_nmap") or {}).get("hosts", []),
    )
    state.set("last_attack", attack)
    return jsonify(attack)
@bp.route("/api/diff/arp")
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


@bp.route("/api/mdns-ssdp", methods=["POST"])
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
