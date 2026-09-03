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

import os
import threading

from flask import Flask

from api import register_blueprints
from core import db
from core.auth import get_runtime_token, register_auth_handlers, require_token
from core.config import HOST, PORT, SECRET_KEY, VERSION, ensure_dirs
from core.logging_setup import get_logger, setup_logging
from core.responses import api_response
from core.state import state

setup_logging()
log = get_logger("harmattan.app")
ensure_dirs()
db.init_db()

# Web auth: users DB (login/password + roles) + session blueprint
from core import users  # noqa: E402
from core.web_auth import bp as web_auth_bp  # noqa: E402

users.init_users_db()

# Re-export for modules that may import from app
_RUNTIME_TOKEN = get_runtime_token()


def run_preflight_checks():
    import shutil
    import sys

    from modules import arp_scanner, nmap_scanner

    checks = {}
    checks["python_version"] = ".".join(map(str, sys.version_info[:3]))
    checks["python_ok"] = sys.version_info >= (3, 10)
    try:
        checks["nmap"] = bool(
            shutil.which("nmap")
            or (hasattr(nmap_scanner, "nmap_available") and nmap_scanner.nmap_available())
        )
    except Exception:
        checks["nmap"] = bool(shutil.which("nmap"))
    try:
        scapy_val = getattr(arp_scanner, "SCAPY_AVAILABLE", False)
        checks["scapy"] = bool(scapy_val)
        log.debug(f"arp_scanner.SCAPY_AVAILABLE = {scapy_val}, checks['scapy'] = {checks['scapy']}")
    except Exception as e:
        log.error(f"Failed to check SCAPY_AVAILABLE: {e}")
        checks["scapy"] = False
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    has_caps = False
    if not is_root:
        try:
            import subprocess

            candidates = [
                sys.executable,
                os.path.realpath(sys.executable),
                "/usr/bin/python3.12",
                "/usr/bin/python3",
            ]
            seen = set()
            for cand in candidates:
                if not cand or cand in seen:
                    continue
                seen.add(cand)
                result = subprocess.run(
                    ["getcap", cand],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                out = (result.stdout or "") + (result.stderr or "")
                if "cap_net_raw" in out or "cap_net_admin" in out:
                    has_caps = True
                    break
        except Exception:
            has_caps = False
    checks["running_as_root"] = is_root or has_caps
    checks["has_caps"] = has_caps

    missing = []
    if not checks["nmap"]:
        missing.append("nmap")
    if not checks["scapy"]:
        missing.append("scapy")
    if not checks["running_as_root"]:
        missing.append("root/CAP_NET_RAW")
    checks["missing"] = missing

    try:
        state.set("preflight", checks)
        state.update(
            features={
                "arp_enabled": bool(checks.get("scapy")),
                "nmap_enabled": bool(checks.get("nmap")),
                "capture_enabled": bool(checks.get("scapy") and checks.get("running_as_root")),
            }
        )
    except Exception:
        pass
    log.info("Preflight checks: %s", checks)
    try:
        from core import notifications as notifier

        notifier.publish({"type": "preflight", "preflight": checks})
    except Exception:
        pass
    return checks


try:
    run_preflight_checks()
except Exception:
    log.exception("Preflight checks failed")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["JSON_SORT_KEYS"] = False

try:
    from flask_socketio import SocketIO

    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
except Exception:
    socketio = None


def _start_notifications_emitter():
    """Background thread: read from in-memory notifier and emit to socketio clients."""
    try:
        if not socketio:
            return
        import threading

        from core import notifications as notifier

        def _worker():
            q = notifier.subscribe()
            try:
                while True:
                    try:
                        ev = q.get()
                        try:
                            socketio.emit("live_event", ev, namespace="/live")
                        except Exception:
                            pass
                    except Exception:
                        pass
            finally:
                try:
                    notifier.unsubscribe(q)
                except Exception:
                    pass

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
    except Exception:
        log.exception("start_notifications_emitter failed")


try:
    _start_notifications_emitter()
except Exception:
    pass

# Web auth blueprint (login/logout + /api/users) — registered BEFORE the API
# blueprints so the session-based login routes take precedence and match.
app.register_blueprint(web_auth_bp)
register_auth_handlers(app)
register_blueprints(app)

# Restore job metadata from SQLite after restart
try:
    from core.jobs import manager as job_manager

    job_manager.hydrate()
except Exception:
    log.debug("job hydrate at startup failed", exc_info=True)


# ---- CLI / Daemon mode ----

_SHOULD_RUN = threading.Event()
_SHOULD_RUN.set()  # by default, run


def _run_server(host: str = HOST, port: int = PORT, https: bool = False):
    """Start the Flask server (blocking)."""
    print("=" * 64)
    protocol = "https" if https else "http"
    print(f"  HARMATTAN v{VERSION} — Network Intelligence Suite")
    print(f"  Interface : {protocol}://{host}:{port}")
    print("  NOTE : ARP / capture → sudo ou CAP_NET_RAW sur python")
    if _RUNTIME_TOKEN:
        print(f"  API Token     : {_RUNTIME_TOKEN}")
        print("  (header X-Harmattan-Token ou cookie httponly — pas de ?token=)")
    print("=" * 64)
    log.info("Starting HARMATTAN v%s on %s:%s", VERSION, host, port)

    ssl_ctx = None
    if https:
        try:
            from core.https_cert import ensure_self_signed_cert

            cert_dir = DATA_DIR / "ssl"
            cert, key = ensure_self_signed_cert(cert_dir)
            ssl_ctx = (str(cert), str(key))
            log.info("HTTPS enabled with self-signed cert from %s", cert_dir)
        except Exception as e:
            log.error("Failed to enable HTTPS: %s", e)

    try:
        if socketio:
            socketio.run(
                app,
                host=host,
                port=port,
                debug=False,
                allow_unsafe_werkzeug=True,
                ssl_context=ssl_ctx,
            )
        else:
            app.run(host=host, port=port, debug=False, threaded=True, ssl_context=ssl_ctx)
    except Exception:
        log.exception("Server failed to start")
        raise


def run_daemon(host: str = HOST, port: int = PORT, https: bool = False):
    """Run Flask in a background thread and wait for stop signal."""
    import threading as _th

    t = _th.Thread(target=_run_server, args=(host, port, https), daemon=True)
    t.start()
    _SHOULD_RUN.wait()  # blocks until stop_daemon() is called


def stop_daemon():
    """Signal the daemon to stop."""
    log.info("Stopping HARMATTAN daemon…")
    _SHOULD_RUN.clear()
    # Force werkzeug to stop
    try:
        import requests as _req

        protocol = "https" if os.environ.get("HARMATTAN_HTTPS") == "1" else "http"
        _req.get(f"{protocol}://127.0.0.1:{PORT}/api/shutdown", timeout=2)
    except Exception:
        pass


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HARMATTAN Network Intelligence Suite")
    # Global options (usable before OR after the subcommand). Each is also added
    # to the `serve` subparser so `app.py serve --port 8088` works; the subparser
    # defaults are None so we fall back to the global values.
    parser.add_argument("--daemon", action="store_true", help="Run in daemon mode (no dev server)")
    parser.add_argument("--host", default=HOST, help=f"Bind address (default: {HOST})")
    parser.add_argument("--port", type=int, default=PORT, help=f"Bind port (default: {PORT})")
    parser.add_argument("--https", type=int, choices=[0, 1], default=0, help="Enable HTTPS (default: 0)")
    sub = parser.add_subparsers(dest="command")

    serve_p = sub.add_parser("serve", help="Start the API server (default)")
    serve_p.add_argument("--daemon", action="store_true", default=None, help=argparse.SUPPRESS)
    serve_p.add_argument("--host", default=None, help=argparse.SUPPRESS)
    serve_p.add_argument("--port", type=int, default=None, help=argparse.SUPPRESS)
    serve_p.add_argument("--https", type=int, choices=[0, 1], default=None, help=argparse.SUPPRESS)

    sub.add_parser("status", help="Show system preflight checks")
    sub.add_parser("token", help="Print the API token")

    arp_p = sub.add_parser("scan-arp", help="Run an ARP scan from CLI")
    arp_p.add_argument("--subnet", default="192.168.1.0/24", help="Target subnet (CIDR)")

    nmap_p = sub.add_parser("scan-nmap", help="Run an Nmap scan from CLI")
    nmap_p.add_argument("--target", default="127.0.0.1", help="Scan target")
    nmap_p.add_argument("--profile", default="quick", help="Scan profile")

    exp_p = sub.add_parser("export", help="Export data in a format")
    exp_p.add_argument("--format", default="csv", choices=["csv", "markdown", "json"], help="Export format")

    sub.add_parser("plugins", help="List discovered plugins")
    sub.add_parser("help", help="Show this help message")

    args = parser.parse_args()

    if args.command is None:
        args.command = "serve"

    # Resolve serve options: subparser value if user supplied it, else global.
    if args.command == "serve":
        if getattr(args, "daemon", None) is None:
            args.daemon = parser.parse_args([]).daemon
        if getattr(args, "host", None) is None:
            args.host = parser.parse_args([]).host
        if getattr(args, "port", None) is None:
            args.port = parser.parse_args([]).port
        if getattr(args, "https", None) is None:
            args.https = parser.parse_args([]).https

    if args.command == "serve":
        if args.daemon:
            run_daemon(host=args.host, port=args.port, https=bool(args.https))
        else:
            _run_server(host=args.host, port=args.port, https=bool(args.https))
    elif args.command == "status":
        # Print preflight checks and exit
        checks = run_preflight_checks()
        import json

        print(json.dumps(checks, indent=2, default=str))
    elif args.command == "token":
        print(_RUNTIME_TOKEN or "No token available")
    elif args.command == "scan-arp":
        # ARP scan from CLI
        import json as _json
        subnet = getattr(args, "subnet", None) or os.environ.get("HARMATTAN_SCAN_SUBNET", "192.168.1.0/24")
        from modules import arp_scanner as _arp
        log.info("CLI ARP scan on %s", subnet)
        results = _arp.scan(subnet=subnet, enrich=True)
        print(_json.dumps(results, indent=2, default=str, ensure_ascii=False))
    elif args.command == "scan-nmap":
        import json as _json
        target = getattr(args, "target", None) or os.environ.get("HARMATTAN_SCAN_TARGET", "127.0.0.1")
        profile = getattr(args, "profile", "quick")
        from modules import nmap_scanner as _nmap
        log.info("CLI Nmap scan on %s (profile=%s)", target, profile)
        results = _nmap.scan(target=target, profile=profile)
        print(_json.dumps(results, indent=2, default=str, ensure_ascii=False))
    elif args.command == "export":
        fmt = getattr(args, "format", "csv")
        from core.export_csv import build_csv_report, build_markdown_report
        from core import state as _state
        import json as _json
        data = {
            "arp": _state.get("last_arp") or {},
            "attack_surface": _state.get("last_attack") or {},
            "vuln": _state.get("last_vuln") or {},
        }
        if fmt == "csv":
            print(build_csv_report(data))
        elif fmt == "markdown":
            print(build_markdown_report(data))
        else:
            print(_json.dumps(data, indent=2, default=str, ensure_ascii=False))
    elif args.command == "plugins":
        from core.plugins import discover_plugins
        import json as _json
        plugs = discover_plugins()
        if not plugs:
            print("No plugins found.")
        else:
            print(_json.dumps(plugs, indent=2, default=str, ensure_ascii=False))
    elif args.command in ("help", None):
        parser.print_help()
