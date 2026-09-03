"""Auth hardening, rate limit, metrics, jobs persistence, blueprints."""
from __future__ import annotations

import os

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HARMATTAN_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("HARMATTAN_REPORTS", str(tmp_path / "reports"))
    monkeypatch.setenv("HARMATTAN_DB", str(tmp_path / "data" / "test.db"))
    monkeypatch.setenv("HARMATTAN_TOKEN", "test-token-xyz")
    monkeypatch.setenv("HARMATTAN_AUTO_TOKEN", "0")
    monkeypatch.setenv("HARMATTAN_ALLOW_QUERY_TOKEN", "0")
    monkeypatch.setenv("HARMATTAN_RATE_LIMIT", "0")  # disable for most tests
    monkeypatch.setenv("HARMATTAN_SECRET", "test-secret-key-32bytes-minimum!!")

    # Fresh imports so config picks up env
    import importlib
    import sys

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
    return app_mod.app.test_client(), "test-token-xyz"


def test_health_public(client):
    c, _tok = client
    r = c.get("/api/health")
    assert r.status_code == 200
    body = r.get_json()
    assert body.get("ok") is True
    assert "version" in body


def test_metrics_public(client):
    c, _tok = client
    r = c.get("/api/metrics")
    assert r.status_code == 200
    body = r.get_json()
    assert body.get("ok") is True
    assert "requests_total" in body

    r2 = c.get("/api/metrics?format=prometheus")
    assert r2.status_code == 200
    assert b"harmattan_up" in r2.data


def test_auth_requires_header_not_query(client):
    c, tok = client
    # no auth
    r = c.get("/api/network-info")
    assert r.status_code == 401
    # query token rejected by default
    r2 = c.get(f"/api/network-info?token={tok}")
    assert r2.status_code == 401
    # header ok
    r3 = c.get("/api/network-info", headers={"X-Harmattan-Token": tok})
    assert r3.status_code == 200
    # cookie ok
    c.set_cookie("harmattan_token", tok)
    r4 = c.get("/api/network-info")
    assert r4.status_code == 200


def test_blueprints_registered(client):
    c, tok = client
    h = {"X-Harmattan-Token": tok}
    for path in (
        "/api/nmap-profiles",
        "/api/tools/catalog",
        "/api/jobs",
        "/api/history",
        "/api/overrides",
    ):
        r = c.get(path, headers=h)
        assert r.status_code == 200, path


def test_job_persist_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("HARMATTAN_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("HARMATTAN_DB", str(tmp_path / "data" / "jobs.db"))
    monkeypatch.setenv("HARMATTAN_SECRET", "test-secret-key-32bytes-minimum!!")
    monkeypatch.setenv("HARMATTAN_TOKEN", "tok")
    monkeypatch.setenv("HARMATTAN_AUTO_TOKEN", "0")

    import importlib
    import sys
    import time

    for mod in list(sys.modules):
        if mod.startswith("core."):
            del sys.modules[mod]

    import core.config as cfg

    importlib.reload(cfg)
    cfg.DATA_DIR.mkdir(parents=True, exist_ok=True)

    import core.db as db

    importlib.reload(db)
    db._initialized = False
    db.init_db()

    import core.jobs as jobs

    importlib.reload(jobs)
    mgr = jobs.JobManager(max_workers=1)

    def work(progress=None):
        if progress:
            progress(50, "half")
        return {"ok": True, "n": 1}

    job = mgr.submit("unit_test", work)
    deadline = time.time() + 5
    while time.time() < deadline:
        j = mgr.get(job.id)
        if j and j.status.value in ("done", "error", "cancelled"):
            break
        time.sleep(0.05)
    j = mgr.get(job.id)
    assert j is not None
    assert j.status == jobs.JobStatus.DONE
    assert j.result == {"ok": True, "n": 1}

    rows = db.list_jobs(limit=5)
    assert any(r["id"] == job.id and r["status"] == "done" for r in rows)


def test_rate_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("HARMATTAN_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("HARMATTAN_DB", str(tmp_path / "data" / "rl.db"))
    monkeypatch.setenv("HARMATTAN_TOKEN", "rl-token")
    monkeypatch.setenv("HARMATTAN_AUTO_TOKEN", "0")
    monkeypatch.setenv("HARMATTAN_ALLOW_QUERY_TOKEN", "0")
    monkeypatch.setenv("HARMATTAN_RATE_LIMIT", "5")
    monkeypatch.setenv("HARMATTAN_SECRET", "test-secret-key-32bytes-minimum!!")

    import importlib
    import sys

    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("core.") or mod.startswith("api."):
            del sys.modules[mod]

    import core.config as cfg

    importlib.reload(cfg)
    cfg.DATA_DIR.mkdir(parents=True, exist_ok=True)

    import core.db as db

    importlib.reload(db)
    db._initialized = False
    db.init_db()

    import core.ratelimit as rl

    importlib.reload(rl)
    rl.limiter.max = 5
    rl.limiter._hits.clear()

    import core.auth as auth

    importlib.reload(auth)

    import app as app_mod

    importlib.reload(app_mod)
    c = app_mod.app.test_client()
    h = {"X-Harmattan-Token": "rl-token"}
    codes = []
    for _ in range(8):
        codes.append(c.get("/api/history", headers=h).status_code)
    assert 429 in codes
    assert codes.count(200) >= 1
