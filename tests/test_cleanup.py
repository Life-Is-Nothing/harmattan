"""Tests for host cleanup / ignore APIs."""
from __future__ import annotations

import importlib
import sys

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HARMATTAN_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("HARMATTAN_REPORTS", str(tmp_path / "reports"))
    monkeypatch.setenv("HARMATTAN_DB", str(tmp_path / "data" / "test.db"))
    monkeypatch.setenv("HARMATTAN_TOKEN", "cleanup-tok")
    monkeypatch.setenv("HARMATTAN_AUTO_TOKEN", "0")
    monkeypatch.setenv("HARMATTAN_ALLOW_QUERY_TOKEN", "0")
    monkeypatch.setenv("HARMATTAN_RATE_LIMIT", "0")
    monkeypatch.setenv("HARMATTAN_SECRET", "test-secret-key-32bytes-minimum!!")

    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("core.") or mod.startswith("api."):
            del sys.modules[mod]

    import core.config as cfg

    importlib.reload(cfg)
    cfg.DATA_DIR.mkdir(parents=True, exist_ok=True)
    cfg.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    import core.db as db

    importlib.reload(db)
    db._initialized = False
    db.init_db()

    import core.auth as auth

    importlib.reload(auth)

    import app as app_mod

    importlib.reload(app_mod)
    app_mod.app.config["TESTING"] = True
    return app_mod.app.test_client(), "cleanup-tok", db


def test_ignore_and_filter(client):
    c, tok, db = client
    h = {"X-Harmattan-Token": tok}
    db.upsert_hosts([{"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.1.10", "vendor": "Test"}])
    assert len(db.list_known_hosts()) == 1

    r = c.post(
        "/api/ignored-hosts",
        headers=h,
        json={"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.1.10", "reason": "test"},
    )
    assert r.status_code == 200
    assert db.list_known_hosts() == []
    assert any(x["key"] == "AA:BB:CC:DD:EE:01" for x in db.list_ignored_hosts())

    filtered = db.filter_ignored_hosts(
        [
            {"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.1.10"},
            {"mac": "AA:BB:CC:DD:EE:02", "ip": "192.168.1.11"},
        ]
    )
    assert len(filtered) == 1
    assert filtered[0]["ip"] == "192.168.1.11"


def test_delete_known_and_clear_scans(client):
    c, tok, db = client
    h = {"X-Harmattan-Token": tok}
    db.upsert_hosts([{"mac": "11:22:33:44:55:66", "ip": "10.0.0.5"}])
    sid = db.save_scan("arp", {"hosts": [], "count": 0})

    r = c.delete("/api/known-hosts/11:22:33:44:55:66", headers=h)
    assert r.status_code == 200
    assert db.list_known_hosts() == []

    r2 = c.delete(f"/api/scans/{sid}", headers=h)
    assert r2.status_code == 200
    assert db.list_scans() == []


def test_session_clear(client):
    c, tok, _db = client
    h = {"X-Harmattan-Token": tok}
    from core.state import state

    state.set("last_arp", {"hosts": [{"ip": "1.2.3.4"}], "count": 1})
    r = c.post("/api/session/clear", headers=h, json={})
    assert r.status_code == 200
    assert state.get("last_arp") in (None, {})
