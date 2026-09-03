"""
HARMATTAN — Web auth blueprint (login/logout/session + admin user management).

Routes:
  GET  /login            login form
  POST /login            authenticate (Flask session)
  GET  /logout           destroy session
  GET  /api/auth/me      current session user (JSON)
  POST /api/auth/password  change own password
  # Admin-only user management (session auth, admin role):
  GET    /api/users
  POST   /api/users
  PATCH  /api/users/<id>
  DELETE /api/users/<id>
"""
from __future__ import annotations

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from core.auth import (
    SESSION_USER_KEY,
    current_user,
    login_required,
    role_required_api,
)
from core.config import VERSION
from core.logging_setup import get_logger
from core.responses import api_response
from core.users import (
    create_user,
    delete_user,
    get_user,
    get_user_by_id,
    is_locked_out,
    list_users,
    role_ok,
    set_password,
    set_role,
    verify_login,
)

log = get_logger("harmattan.web_auth")

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    locked = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        next_url = request.args.get("next") or request.form.get("next") or "/"

        if not username or not password:
            error = "Nom d'utilisateur et mot de passe requis."
        else:
            locked = is_locked_out(username)
            if locked:
                error = f"Trop de tentatives. Réessayez dans {locked} s."
            else:
                try:
                    actor = verify_login(username, password)
                    session.clear()
                    session[SESSION_USER_KEY] = actor["id"]
                    session.permanent = False
                    log.info("Web login: user=%s role=%s", actor["username"], actor["role"])
                    if actor["must_change"]:
                        return redirect(url_for("auth.change_password"))
                    # Avoid open-redirect: only allow local paths
                    if next_url.startswith("/") and not next_url.startswith("//"):
                        return redirect(next_url)
                    return redirect(url_for("index"))
                except ValueError as e:
                    error = str(e)

    return render_template(
        "login.html",
        version=VERSION,
        error=error,
    ), (401 if error else 200)


@bp.route("/logout")
def logout():
    username = None
    user = current_user()
    if user:
        username = user.get("username")
    session.clear()
    log.info("Web logout: user=%s", username)
    return redirect(url_for("auth.login"))


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = current_user()
    error = None
    ok = None
    if request.method == "POST":
        current_pw = request.form.get("current_password") or ""
        new_pw = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""
        if not new_pw or new_pw != confirm:
            error = "Les nouveaux mots de passe ne correspondent pas."
        elif len(new_pw) < 4:
            error = "Mot de passe trop court (min 4 caractères)."
        else:
            try:
                verify_login(user["username"], current_pw)  # re-verify current pw
            except ValueError:
                error = "Mot de passe actuel incorrect."
            else:
                set_password(user["id"], new_pw, clear_must_change=True)
                ok = "Mot de passe modifié avec succès."
    return render_template(
        "change_password.html",
        version=VERSION,
        error=error,
        ok=ok,
        must_change=bool(user.get("must_change")),
    )


# ---------------------------------------------------------------------------
# Session / auth info (JSON)
# ---------------------------------------------------------------------------
@bp.route("/api/auth/me")
def api_auth_me():
    user = current_user()
    if not user:
        return api_response(error="unauthorized", message="Non connecté.", status=401)
    return jsonify({
        "ok": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "must_change": bool(user["must_change"]),
        },
    })


@bp.route("/api/auth/password", methods=["POST"])
@login_required
def api_change_password():
    user = current_user()
    data = request.get_json(force=True, silent=True) or {}
    current_pw = data.get("current_password") or ""
    new_pw = data.get("new_password") or ""
    if not new_pw or len(new_pw) < 4:
        return api_response(error="invalid_password", message="Mot de passe trop court (min 4).", status=400)
    try:
        verify_login(user["username"], current_pw)
    except ValueError:
        return api_response(error="bad_current", message="Mot de passe actuel incorrect.", status=400)
    set_password(user["id"], new_pw, clear_must_change=True)
    return api_response(message="Mot de passe modifié.")


# ---------------------------------------------------------------------------
# Admin-only user management
# ---------------------------------------------------------------------------
@bp.route("/api/users", methods=["GET"])
@role_required_api
def api_users_list():
    return jsonify({"ok": True, "users": list_users()})


@bp.route("/api/users", methods=["POST"])
@role_required_api
def api_users_create():
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "viewer"
    try:
        user = create_user(username, password, role)
    except ValueError as e:
        return api_response(error="invalid", message=str(e), status=400)
    log.info("Web admin created user %s role=%s", username, role)
    return api_response(message="Utilisateur créé.", data={"user": user})


@bp.route("/api/users/<int:user_id>", methods=["GET"])
@role_required_api
def api_users_get(user_id: int):
    u = get_user_by_id(user_id)
    if not u:
        return api_response(error="not_found", status=404)
    u.pop("password_hash", None)
    return jsonify({"ok": True, "user": u})


@bp.route("/api/users/<int:user_id>", methods=["PATCH"])
@role_required_api
def api_users_update(user_id: int):
    u = get_user_by_id(user_id)
    if not u:
        return api_response(error="not_found", status=404)
    data = request.get_json(force=True, silent=True) or {}
    acting = current_user()
    # Prevent self-demotion / self-delete of the last admin.
    if u["username"] == "admin" and (data.get("role") and data["role"] != "admin"):
        return api_response(
            error="forbidden",
            message="Impossible de retirer le rôle admin au compte admin principal.",
            status=403,
        )
    if "role" in data and data["role"]:
        set_role(user_id, data["role"])
    if "password" in data and data["password"]:
        set_password(user_id, data["password"], clear_must_change=True)
    log.info("Web admin updated user id=%s by %s", user_id, acting.get("username"))
    return api_response(message="Utilisateur mis à jour.")


@bp.route("/api/users/<int:user_id>", methods=["DELETE"])
@role_required_api
def api_users_delete(user_id: int):
    u = get_user_by_id(user_id)
    if not u:
        return api_response(error="not_found", status=404)
    acting = current_user()
    if u["username"] == "admin":
        return api_response(
            error="forbidden", message="Impossible de supprimer le compte admin principal.", status=403
        )
    if acting and acting["id"] == user_id:
        return api_response(error="forbidden", message="Impossible de supprimer votre propre compte.", status=403)
    delete_user(user_id)
    log.info("Web admin deleted user id=%s by %s", user_id, acting.get("username"))
    return api_response(message="Utilisateur supprimé.")
