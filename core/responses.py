"""Standard JSON API response helper."""
from __future__ import annotations

from flask import jsonify


def api_response(data=None, error=None, message=None, status=200, **extra):
    body = {"ok": error is None}
    if error:
        body["error"] = error
    if message:
        body["message"] = message
    if data is not None:
        body["data"] = data
    body.update(extra)
    return jsonify(body), status
