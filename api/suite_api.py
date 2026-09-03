"""
HARMATTAN v3.21 — Playbooks, baseline/drift, risk, passive, pcap ring, MISP, webhooks.
"""
from __future__ import annotations

import json
import os
from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from api.deps import REPORTS_DIR, VERSION, api_response, db, job_manager, log, state
from core.alerts import notify as alert_notify
from modules import attack_surface, baseline as baseline_mod
from modules import export_misp
from modules import network_info
from modules import passive_recon
from modules import pcap_ring
from modules import playbooks as playbooks_mod
from modules import risk_dashboard
from modules.mdns_discovery import discover_mdns_ssdp

bp = Blueprint("suite_ext", __name__)


# ─── Playbooks ───────────────────────────────────────────────────────
@bp.route("/api/playbooks")
def api_playbooks_list():
    return jsonify({"ok": True, "playbooks": playbooks_mod.list_playbooks()})


@bp.route("/api/playbooks/<playbook_id>", methods=["POST"])
def api_playbooks_run(playbook_id: str):
    data = request.get_json(force=True, silent=True) or {}
    iface = data.get("iface") or None
    subnet = data.get("subnet") or network_info.get_local_subnet(iface)
    async_mode = bool(data.get("async", True))

    def _run(progress=None):
        from api.scan import _do_arp_scan
        from modules import nmap_scanner, report as report_mod

        def do_arp(sub, ifc, enrich, light):
            return _do_arp_scan(sub, ifc, enrich, light, progress=progress)

        def do_nmap(target, profile):
            # "service" alias → quick profile with version detection
            prof = profile or "quick"
            if prof == "service":
                prof = "quick"
            result = nmap_scanner.run_scan(target, profile=prof, progress=progress)
            if not result.get("error"):
                state.set("last_nmap", result)
                db.save_scan("nmap", result)
            return result

        def do_mdns():
            r = discover_mdns_ssdp(timeout=2.5)
            state.set("last_mdns", r)
            return r

        def do_passive(timeout=3.0):
            r = passive_recon.passive_discover(timeout=timeout)
            state.set("last_passive", r)
            return r

        def do_attack(arp_h, nmap_h):
            if not arp_h:
                arp_h = (state.get("last_arp") or {}).get("hosts") or []
            if not nmap_h:
                nmap_h = (state.get("last_nmap") or {}).get("hosts") or []
            atk = attack_surface.build_attack_surface(arp_h, nmap_h)
            state.set("last_attack", atk)
            db.save_scan("attack", atk)
            return atk

        def do_baseline_save(label):
            snap = baseline_mod.build_snapshot(
                (state.get("last_arp") or {}).get("hosts"),
                (state.get("last_nmap") or {}).get("hosts"),
                label=label,
            )
            return db.save_baseline(label, snap, activate=True)

        def do_baseline_diff():
            return _diff_active_baseline()

        def do_report():
            try:
                html = report_mod.build_html_report(
                    network=state.get("last_network") or {},
                    arp=state.get("last_arp") or {},
                    nmap=state.get("last_nmap") or {},
                    attack=state.get("last_attack") or {},
                    vuln=state.get("last_vuln") or {},
                )
                out = REPORTS_DIR / f"playbook_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                out.write_text(html if isinstance(html, str) else str(html), encoding="utf-8")
                return {"ok": True, "path": str(out), "file": out.name}
            except TypeError:
                # older signature variants
                try:
                    html = report_mod.build_html_report(
                        state.get("last_network") or {},
                        state.get("last_arp") or {},
                        state.get("last_attack") or {},
                        state.get("last_vuln") or {},
                    )
                    out = REPORTS_DIR / f"playbook_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                    out.write_text(html if isinstance(html, str) else str(html), encoding="utf-8")
                    return {"ok": True, "path": str(out), "file": out.name}
                except Exception as e:
                    return {"ok": False, "error": str(e)[:160]}
            except Exception as e:
                return {"ok": False, "error": str(e)[:160]}

        def do_risk():
            return _build_risk()

        out = playbooks_mod.run_playbook(
            playbook_id,
            subnet=subnet,
            iface=iface,
            progress=progress,
            ctx={
                "do_arp": do_arp,
                "do_nmap": do_nmap,
                "do_mdns": do_mdns,
                "do_passive": do_passive,
                "do_attack": do_attack,
                "do_baseline_save": do_baseline_save,
                "do_baseline_diff": do_baseline_diff,
                "do_report": do_report,
                "do_risk": do_risk,
            },
        )
        db.push_history("playbook", f"{playbook_id} ok={out.get('ok')}")
        state.set("last_playbook", out)
        if out.get("ok"):
            alert_notify(f"Playbook {playbook_id} terminé", source="playbook", severity="info")
            _dispatch_webhooks("playbook", out)
        return out

    if not async_mode:
        return jsonify(_run())

    job = job_manager.submit("playbook", _run, message=f"Playbook {playbook_id}")
    return jsonify({"ok": True, "job_id": job.id, "status": job.status.value, "playbook": playbook_id})


# ─── Baseline / drift ────────────────────────────────────────────────
def _diff_active_baseline() -> dict:
    base = db.get_baseline(active=True)
    if not base:
        return {"ok": False, "error": "no_active_baseline", "hint": "POST /api/baseline d'abord"}
    current = baseline_mod.build_snapshot(
        (state.get("last_arp") or {}).get("hosts"),
        (state.get("last_nmap") or {}).get("hosts"),
        label="current",
    )
    diff = baseline_mod.diff_baseline(base["payload"], current)
    diff["baseline_id"] = base["id"]
    state.set("last_drift", diff)
    sev = baseline_mod.severity_for_drift(diff)
    if (diff.get("summary") or {}).get("has_drift"):
        s = diff["summary"]
        alert_notify(
            f"Drift réseau: +{s.get('appeared', 0)} / -{s.get('disappeared', 0)} / ~{s.get('changed', 0)}",
            source="baseline",
            severity=sev,
        )
        _dispatch_webhooks("drift", diff)
    return diff


@bp.route("/api/baseline", methods=["GET", "POST"])
def api_baseline():
    if request.method == "GET":
        return jsonify({"ok": True, "baselines": db.list_baselines(), "active": db.get_baseline(active=True)})

    data = request.get_json(force=True, silent=True) or {}
    label = (data.get("label") or "baseline").strip() or "baseline"
    activate = bool(data.get("activate", True))
    arp_h = (state.get("last_arp") or {}).get("hosts") or data.get("hosts")
    nmap_h = (state.get("last_nmap") or {}).get("hosts")
    snap = baseline_mod.build_snapshot(arp_h, nmap_h, label=label, meta={"version": VERSION})
    saved = db.save_baseline(label, snap, activate=activate)
    db.push_history("baseline", f"Saved {label} ({snap.get('asset_count')} assets)")
    return jsonify({"ok": True, "baseline": saved, "snapshot": {"asset_count": snap["asset_count"], "fingerprint": snap["fingerprint"]}})


@bp.route("/api/baseline/<int:baseline_id>", methods=["GET", "DELETE"])
def api_baseline_one(baseline_id: int):
    if request.method == "DELETE":
        ok = db.delete_baseline(baseline_id)
        return jsonify({"ok": ok})
    b = db.get_baseline(baseline_id=baseline_id)
    if not b:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "baseline": b})


@bp.route("/api/baseline/<int:baseline_id>/activate", methods=["POST"])
def api_baseline_activate(baseline_id: int):
    ok = db.set_active_baseline(baseline_id)
    return jsonify({"ok": ok})


@bp.route("/api/baseline/diff", methods=["GET", "POST"])
def api_baseline_diff():
    return jsonify(_diff_active_baseline())


# ─── Risk dashboard ──────────────────────────────────────────────────
def _build_risk() -> dict:
    return risk_dashboard.build_risk_dashboard(
        arp=state.get("last_arp"),
        nmap=state.get("last_nmap"),
        attack=state.get("last_attack"),
        drift=state.get("last_drift"),
        known_count=len(db.list_known_hosts()),
        new_devices=state.get("new_devices") or [],
        tags_summary=db.tags_summary(),
    )


@bp.route("/api/risk")
def api_risk():
    dash = _build_risk()
    state.set("last_risk", dash)
    return jsonify(dash)


# ─── Tags filter ─────────────────────────────────────────────────────
@bp.route("/api/tags")
def api_tags():
    return jsonify({"ok": True, "tags": db.tags_summary()})


@bp.route("/api/tags/<tag>/hosts")
def api_tags_hosts(tag: str):
    return jsonify({"ok": True, "tag": tag, "hosts": db.hosts_by_tag(tag)})


# ─── Passive recon ────────────────────────────────────────────────────
@bp.route("/api/passive", methods=["POST"])
def api_passive():
    data = request.get_json(force=True, silent=True) or {}
    timeout = float(data.get("timeout") or 4.0)
    async_mode = bool(data.get("async", False))

    def _run(progress=None):
        r = passive_recon.passive_discover(timeout=timeout, progress=progress)
        state.set("last_passive", r)
        db.save_scan("passive", r)
        db.push_history("passive", f"{r.get('count', 0)} hôte(s) passifs")
        return r

    if async_mode:
        job = job_manager.submit("passive", _run, message="Passive recon")
        return jsonify({"ok": True, "job_id": job.id})
    return jsonify(_run())


@bp.route("/api/passive/monitor", methods=["GET", "POST", "DELETE"])
def api_passive_monitor():
    if request.method == "GET":
        return jsonify(passive_recon.passive_monitor_status())
    if request.method == "DELETE":
        return jsonify(passive_recon.stop_passive_monitor())
    data = request.get_json(force=True, silent=True) or {}
    return jsonify(passive_recon.start_passive_monitor(interval=float(data.get("interval") or 30)))


# ─── PCAP ring ───────────────────────────────────────────────────────
@bp.route("/api/pcap/ring")
def api_pcap_status():
    return jsonify(pcap_ring.status())


@bp.route("/api/pcap/ring/open", methods=["POST"])
def api_pcap_open():
    data = request.get_json(force=True, silent=True) or {}
    return jsonify(pcap_ring.open_writer(prefix=data.get("prefix") or "capture"))


@bp.route("/api/pcap/ring/close", methods=["POST"])
def api_pcap_close():
    return jsonify(pcap_ring.close_writer())


@bp.route("/api/pcap/ring/search")
def api_pcap_search():
    ip = request.args.get("ip")
    port = request.args.get("port")
    proto = request.args.get("protocol") or request.args.get("proto")
    limit = int(request.args.get("limit") or 200)
    port_i = int(port) if port and str(port).isdigit() else None
    return jsonify(pcap_ring.search(ip=ip, port=port_i, protocol=proto, limit=limit))


@bp.route("/api/pcap/ring/ingest", methods=["POST"])
def api_pcap_ingest():
    """Ingest current traffic buffer into ring."""
    packets = []
    cap = state.capture
    if cap:
        try:
            if hasattr(cap, "packet_index_for_correlation"):
                packets = cap.packet_index_for_correlation(limit=2000)
            elif hasattr(cap, "get_packets"):
                packets = cap.get_packets(limit=2000)
        except Exception as e:
            log.debug("pcap ingest: %s", e)
    data = request.get_json(force=True, silent=True) or {}
    if data.get("packets"):
        packets = data["packets"]
    n = pcap_ring.ingest_from_capture(packets or [])
    return jsonify({"ok": True, "ingested": n, "ring": pcap_ring.status()})


@bp.route("/api/pcap/ring/clear", methods=["POST"])
def api_pcap_clear():
    return jsonify(pcap_ring.clear_ring())


# ─── MISP / Elastic export ───────────────────────────────────────────
@bp.route("/api/export/misp")
def api_export_misp():
    hosts = (state.get("last_arp") or {}).get("hosts") or []
    attack = state.get("last_attack") or {}
    findings = db.list_findings(limit=100)
    event = export_misp.build_misp_event(
        hosts=hosts,
        attack=attack,
        findings=findings,
        info=request.args.get("info") or "HARMATTAN network audit export",
        org=request.args.get("org") or "HARMATTAN",
    )
    if request.args.get("download") == "1":
        out = REPORTS_DIR / f"misp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(event, ensure_ascii=False, indent=2), encoding="utf-8")
        return jsonify({"ok": True, "file": out.name, "attributes": len(event["Event"]["Attribute"])})
    return jsonify({"ok": True, "event": event})


@bp.route("/api/export/elastic")
def api_export_elastic():
    hosts = (state.get("last_arp") or {}).get("hosts") or []
    attack = state.get("last_attack") or {}
    index = request.args.get("index") or "harmattan-assets"
    body = export_misp.build_elastic_bulk(hosts=hosts, attack=attack, index=index)
    if request.args.get("download") == "1":
        out = REPORTS_DIR / f"elastic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ndjson"
        out.write_text(body, encoding="utf-8")
        return jsonify({"ok": True, "file": out.name, "bytes": len(body)})
    return Response(body, mimetype="application/x-ndjson")


# ─── Webhooks ────────────────────────────────────────────────────────
def _dispatch_webhooks(event_type: str, payload: dict) -> list[dict]:
    results = []
    try:
        import urllib.request

        for wh in db.list_webhooks():
            if not wh.get("enabled"):
                continue
            events = (wh.get("events") or "*").split(",")
            events = [e.strip() for e in events]
            if "*" not in events and event_type not in events:
                continue
            url = wh["url"]
            body = {
                "source": "harmattan",
                "event": event_type,
                "version": VERSION,
                "time": datetime.now().isoformat(timespec="seconds"),
                "payload": payload,
            }
            # Discord / Slack friendly text
            text = f"[HARMATTAN] {event_type}: {json.dumps(payload, default=str)[:400]}"
            try:
                if "discord.com/api/webhooks" in url or "discordapp.com" in url:
                    data = json.dumps({"content": text[:1900]}).encode()
                elif "hooks.slack.com" in url:
                    data = json.dumps({"text": text[:3000]}).encode()
                elif "api.telegram.org" in url:
                    data = json.dumps(body, default=str).encode()
                else:
                    data = json.dumps(body, default=str).encode()
                req = urllib.request.Request(
                    url, data=data, headers={"Content-Type": "application/json"}, method="POST"
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    results.append({"id": wh["id"], "ok": 200 <= resp.status < 300, "status": resp.status})
            except Exception as e:
                results.append({"id": wh["id"], "ok": False, "error": str(e)[:120]})
    except Exception as e:
        log.debug("webhooks: %s", e)
    return results


@bp.route("/api/webhooks", methods=["GET", "POST"])
def api_webhooks():
    if request.method == "GET":
        return jsonify({"ok": True, "webhooks": db.list_webhooks()})
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "webhook").strip()
    url = (data.get("url") or "").strip()
    if not url.startswith("http"):
        return jsonify({"ok": False, "error": "invalid_url"}), 400
    wh = db.add_webhook(name, url, data.get("events") or "*")
    return jsonify({"ok": True, "webhook": wh})


@bp.route("/api/webhooks/<int:webhook_id>", methods=["DELETE"])
def api_webhooks_delete(webhook_id: int):
    return jsonify({"ok": db.delete_webhook(webhook_id)})


@bp.route("/api/webhooks/test", methods=["POST"])
def api_webhooks_test():
    results = _dispatch_webhooks("test", {"message": "HARMATTAN webhook test", "version": VERSION})
    return jsonify({"ok": True, "results": results})


# ─── Suite bridge helpers (threat/logai correlation) ─────────────────
@bp.route("/api/suite/inventory")
def api_suite_inventory():
    """Compact inventory for Threat/LogAI correlation."""
    hosts = (state.get("last_arp") or {}).get("hosts") or db.list_known_hosts()
    return jsonify({
        "ok": True,
        "version": VERSION,
        "hosts": [
            {
                "ip": h.get("ip"),
                "mac": h.get("mac"),
                "hostname": h.get("hostname"),
                "vendor": h.get("vendor"),
                "role": h.get("role"),
                "tags": h.get("tags") or [],
            }
            for h in hosts
        ],
        "count": len(hosts),
        "risk": state.get("last_risk") or _build_risk(),
    })
