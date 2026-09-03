"""Authentication, rate limiting, request gates, and error handlers."""
from __future__ import annotations

from functools import wraps

from flask import g, jsonify, redirect, request, session, url_for

from core.config import (
    ALLOW_QUERY_TOKEN,
    API_TOKEN,
    AUTO_TOKEN,
    PUBLIC_API_PATHS,
    RATE_LIMIT_PER_MIN,
    VERSION,
    load_or_create_token,
)
from core.logging_setup import get_logger
from core.metrics import metrics
from core.ratelimit import limiter
from core.responses import api_response
from core.validation import ValidationError

log = get_logger("harmattan.auth")

_RUNTIME_TOKEN = API_TOKEN or (load_or_create_token() if AUTO_TOKEN else "")

if _RUNTIME_TOKEN:
    log.warning("=" * 60)
    log.warning("🔐 HARMATTAN TOKEN (stable across restarts):")
    log.warning(f"   {_RUNTIME_TOKEN}")
    log.warning("   Use: curl -H 'X-Harmattan-Token: <token>' http://127.0.0.1:8088/api/health")
    log.warning("   Or set HARMATTAN_TOKEN / data/.api_token")
    if not ALLOW_QUERY_TOKEN:
        log.warning("   Query ?token= is DISABLED (set HARMATTAN_ALLOW_QUERY_TOKEN=1 to allow)")
    log.warning("=" * 60)


def get_runtime_token() -> str:
    return _RUNTIME_TOKEN


def _extract_token(req) -> str | None:
    """Prefer header, then cookie. Query string only if explicitly allowed."""
    header = req.headers.get("X-Harmattan-Token")
    if header:
        return header
    auth = req.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    cookie = req.cookies.get("harmattan_token")
    if cookie:
        return cookie
    if ALLOW_QUERY_TOKEN:
        return req.args.get("token")
    return None


def check_request_auth(req) -> tuple[bool, dict | None]:
    """Return (ok, actor_info). actor_info has at least a 'user' key when ok."""
    if not _RUNTIME_TOKEN:
        return True, {"user": "anonymous"}
    token = _extract_token(req)
    if token == _RUNTIME_TOKEN:
        return True, {"user": "token"}
    try:
        import sys as _sys
        from pathlib import Path as _P

        _sys.path.insert(0, str(_P.home() / "harmattan-common"))
        from harmattan_common.sso import authorize as _sso_auth

        ok, info = _sso_auth(req, _RUNTIME_TOKEN, "X-Harmattan-Token", "harmattan_token")
        if ok and info:
            return True, info
    except Exception:
        pass
    return False, None


def require_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _RUNTIME_TOKEN:
            return fn(*args, **kwargs)
        token = _extract_token(request)
        if token != _RUNTIME_TOKEN:
            return api_response(error="unauthorized", message="Token invalide.", status=401)
        return fn(*args, **kwargs)

    return wrapper


def _client_key() -> str:
    # Prefer X-Forwarded-For first hop when behind a trusted proxy
    xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return xff or (request.remote_addr or "unknown")


# ---------------------------------------------------------------------------
# Web (session-based) auth — coexists with token auth for API calls
# ---------------------------------------------------------------------------
SESSION_USER_KEY = "harmattan_user"


def current_user() -> dict | None:
    """Return the logged-in web user dict (or None)."""
    uid = session.get(SESSION_USER_KEY)
    if not uid:
        return None
    try:
        from core.users import get_user_by_id

        user = get_user_by_id(int(uid))
    except Exception:
        return None
    if not user:
        session.pop(SESSION_USER_KEY, None)
        return None
    return user


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            if request.path.startswith("/api"):
                return api_response(
                    error="unauthorized",
                    message="Connexion requise.",
                    status=401,
                )
            return redirect(url_for("auth.login", next=request.path))
        return fn(*args, **kwargs)

    return wrapper


def role_required(*roles):
    """Require one of the given web roles. For API routes returns 403 JSON."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None:
                if request.path.startswith("/api"):
                    return api_response(error="unauthorized", message="Connexion requise.", status=401)
                return redirect(url_for("auth.login", next=request.path))
            if user.get("role") not in roles:
                if request.path.startswith("/api"):
                    return api_response(
                        error="forbidden",
                        message="Privilèges insuffisants (rôle requis: " + ", ".join(roles) + ").",
                        status=403,
                    )
                return redirect(url_for("index"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def role_required_api(fn):
    """Admin-only for API routes that mutate users — 403 JSON otherwise."""
    return role_required("admin")(fn)


def register_auth_handlers(app):
    @app.before_request
    def _auth_gate():
        if request.path == "/" or request.path.startswith("/static"):
            return None
        if not request.path.startswith("/api"):
            return None

        # Rate limit API (except health/metrics)
        if RATE_LIMIT_PER_MIN > 0 and request.path not in PUBLIC_API_PATHS:
            ok_rl, retry = limiter.allow(_client_key())
            if not ok_rl:
                metrics.record_request(request.path, 429)
                resp = jsonify({
                    "ok": False,
                    "error": "rate_limited",
                    "message": "Trop de requêtes. Réessayez plus tard.",
                    "retry_after": retry,
                })
                resp.status_code = 429
                resp.headers["Retry-After"] = str(retry)
                return resp

        if request.path in PUBLIC_API_PATHS:
            return None

        ok, info = check_request_auth(request)
        if ok:
            g.actor = (info or {}).get("user") or "anonymous"
            if info and info.get("user") not in ("token", "anonymous"):
                g.identity = info
            elif info and info.get("user") == "token":
                g.actor = "token"
            return None
        metrics.record_request(request.path, 401)
        return jsonify(
            {
                "ok": False,
                "error": "unauthorized",
                "message": "Token requis (header X-Harmattan-Token, cookie, ou Identity SSO).",
            }
        ), 401

    @app.after_request
    def _security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "SAMEORIGIN"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Harmattan-Version"] = VERSION
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if request.path.startswith("/api"):
            try:
                metrics.record_request(request.path, resp.status_code)
            except Exception:
                pass
        if _RUNTIME_TOKEN and request.path == "/":
            resp.set_cookie(
                "harmattan_token",
                _RUNTIME_TOKEN,
                httponly=True,
                samesite="Strict",
                max_age=86400 * 7,
            )
        return resp

    @app.errorhandler(ValidationError)
    def _validation_error(e: ValidationError):
        return api_response(error=e.code, message=e.message, status=400)

    @app.errorhandler(404)
    def _not_found(e):
        return api_response(error="not_found", message="Route introuvable.", status=404)

    @app.errorhandler(405)
    def _method_not_allowed(e):
        return api_response(error="method_not_allowed", message="Méthode HTTP non autorisée.", status=405)

    @app.errorhandler(Exception)
    def _unhandled(e: Exception):
        from werkzeug.exceptions import HTTPException

        if isinstance(e, HTTPException):
            return api_response(
                error=(e.name or "http_error").lower().replace(" ", "_"),
                message=e.description or str(e),
                status=e.code or 500,
            )
        log.exception("Unhandled error")
        return api_response(error="internal", message=str(e), status=500)
