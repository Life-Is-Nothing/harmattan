"""Harmattan API blueprints — registered under /api/ and /api/v1/."""


def register_blueprints(app):
    from api.ai_api import bp as ai_bp
    from api.export_api import bp as export_bp
    from api.feature_api import bp as feature_bp
    from api.intel_api import bp as intel_bp
    from api.scan import bp as scan_bp
    from api.suite_api import bp as suite_bp
    from api.system import bp as system_bp
    from api.tools_api import bp as tools_bp
    from api.topology_api import bp as topology_bp
    from api.traffic_api import bp as traffic_bp

    # Register under /api/ (legacy)
    app.register_blueprint(system_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(topology_bp)
    app.register_blueprint(tools_bp)
    app.register_blueprint(traffic_bp)
    app.register_blueprint(intel_bp)
    app.register_blueprint(export_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(suite_bp)
    app.register_blueprint(feature_bp)

    # Register v1-specific blueprints
    register_v1_blueprints(app)


# Notification channels API (v1)
from flask import Blueprint, jsonify, request

notify_channels_bp = Blueprint("notify_channels", __name__)


@notify_channels_bp.route("/api/v1/notification-channels", methods=["GET"])
def list_channels():
    from api.deps import db
    return jsonify(db.list_notification_channels())


@notify_channels_bp.route("/api/v1/notification-channels", methods=["POST"])
def create_channel():
    from api.deps import db
    data = request.get_json(force=True, silent=True) or {}
    canal = data.get("canal", "")
    label = data.get("label", canal)
    config = data.get("config", {})
    events = data.get("events", "*")
    enabled = 1 if data.get("enabled", True) else 0
    ch_id = db.save_notification_channel(canal, label, config, events, enabled)
    return jsonify({"id": ch_id, "ok": True})


@notify_channels_bp.route("/api/v1/notification-channels/<int:ch_id>", methods=["DELETE"])
def delete_channel(ch_id: int):
    from api.deps import db
    db.delete_notification_channel(ch_id)
    return jsonify({"ok": True})


@notify_channels_bp.route("/api/v1/notification-channels/<int:ch_id>", methods=["PUT"])
def update_channel(ch_id: int):
    from api.deps import db
    data = request.get_json(force=True, silent=True) or {}
    db.update_notification_channel(ch_id, **data)
    return jsonify({"ok": True})


@notify_channels_bp.route("/api/v1/plugins", methods=["GET"])
def list_plugins():
    from api.deps import db
    return jsonify(db.list_plugins())


@notify_channels_bp.route("/api/v1/plugins/<name>/toggle", methods=["POST"])
def toggle_plugin(name: str):
    from api.deps import db
    data = request.get_json(force=True, silent=True) or {}
    db.toggle_plugin(name, data.get("enabled", True))
    return jsonify({"ok": True})


@notify_channels_bp.route("/api/v1/exports", methods=["GET"])
def list_exports():
    from api.deps import db
    return jsonify(db.list_exports())


# Register v1-specific blueprints
def register_v1_blueprints(app_obj):
    app_obj.register_blueprint(notify_channels_bp)
