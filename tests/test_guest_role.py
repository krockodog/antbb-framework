"""Hosted Gast role: deny-by-default allowlist, payload gates, rate limit."""
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from antbb import hosted, webauth, webguard

PASSWORD = "testserver-password-only"
ORIGIN = {"origin": "https://testserver"}


@pytest.fixture
def hosted_env(monkeypatch, tmp_path):
    for name in ("ANTBB_ADMIN_PASSWORD", "ANTBB_TESTING", "ANTBB_EXPOSE", "YQ_EXPOSE",
                 "ANTBB_AUTH", "ANTBB_COOKIE_SECURE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTBB_HOSTED", "1")
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD_HASH", webauth.format_password_hash(PASSWORD))
    monkeypatch.setenv("ANTBB_DB", str(tmp_path / "guest.db"))
    webauth.reset_login_throttle()
    hosted.reset_guest_rate()
    yield
    webauth.reset_login_throttle()
    hosted.reset_guest_rate()


def test_guest_aliases_and_allowlist():
    assert hosted.is_guest("viewer")
    assert hosted.is_guest("guest_user")
    assert not hosted.is_guest("admin")
    assert hosted.guest_write_allowed("/api/targets/2/scan", "POST")
    assert hosted.guest_write_allowed("/api/targets/2/scan/cancel", "POST")
    assert hosted.guest_write_allowed("/api/blue/run", "POST")
    assert hosted.guest_write_allowed("/osint/run", "POST")
    assert hosted.guest_write_allowed("/yellow/upload", "POST")
    assert hosted.guest_write_allowed("/api/reports/generate", "POST")
    assert hosted.guest_write_allowed("/api/thing", "GET")
    assert not hosted.guest_write_allowed("/api/targets", "POST")
    assert not hosted.guest_write_allowed("/api/targets/2/scopes", "POST")
    assert not hosted.guest_write_allowed("/api/targets/2/oversight", "POST")
    assert not hosted.guest_write_allowed("/api/targets/2/mode", "POST")
    assert not hosted.guest_write_allowed("/isms", "POST")
    assert not hosted.guest_write_allowed("/api/blue/findings/1/apply", "POST")
    assert not hosted.guest_write_allowed("/api/undo", "POST")
    assert not hosted.guest_write_allowed("/api/brain/logs", "DELETE")
    assert not hosted.guest_write_allowed("/api/remote/tunnel/start", "POST")
    assert hosted.guest_payload_denied("/api/targets/2/scan", {"active": True})
    assert hosted.guest_payload_denied("/api/targets/2/scan", {"offensive": True})
    assert hosted.guest_payload_denied("/api/targets/2/scan", {"oversight_ack": True})
    assert hosted.guest_payload_denied("/api/blue/run", {"apply_fixes": True})
    assert hosted.guest_payload_denied("/api/blue/run", {"depth": "intense"})
    assert hosted.guest_payload_denied("/api/targets/2/scan", {"depth": "light"}) is None
    assert hosted.guest_payload_denied("/api/blue/run", {"apply_fixes": False, "depth": "light"}) is None


def _app(store):
    app = FastAPI()

    @app.get("/api/thing")
    def thing():
        return {"ok": True}

    @app.post("/api/thing")
    def post_thing():
        return {"ok": True}

    @app.get("/api/targets")
    def targets():
        return [{"id": 2, "name": "antbb-selftest-isms"}]

    @app.post("/api/targets")
    def add_target():
        return {"ok": True, "id": 99}

    @app.post("/api/targets/{tid}/scopes")
    def scopes(tid: int):
        return {"ok": True}

    @app.delete("/api/targets/{tid}/scopes/{sid}")
    def del_scope(tid: int, sid: int):
        return {"ok": True}

    @app.post("/api/targets/{tid}/oversight")
    def oversight(tid: int):
        return {"ok": True}

    @app.post("/api/targets/{tid}/mode")
    def mode(tid: int):
        return {"ok": True}

    @app.post("/api/targets/{tid}/scan")
    def scan(tid: int):
        return JSONResponse({"ok": True, "status": "running", "target_id": tid}, status_code=202)

    @app.post("/api/targets/{tid}/scan/cancel")
    def cancel(tid: int):
        return {"ok": True, "status": "cancelling"}

    @app.post("/api/blue/run")
    def blue():
        return {"ok": True, "run_id": "blue-test"}

    @app.post("/api/blue/findings/{fid}/apply")
    def apply(fid: int):
        return {"ok": True}

    @app.post("/osint/run")
    def osint():
        return {"ok": True}

    @app.post("/yellow/upload")
    def yellow():
        return JSONResponse({"ok": True}, status_code=200)

    @app.post("/api/reports/generate")
    def gen_report():
        return {"ok": True}

    @app.get("/api/brain/logs")
    def logs():
        return {"ok": True, "events": []}

    @app.delete("/api/brain/logs")
    def del_logs():
        return {"ok": True}

    @app.get("/isms")
    def isms_get(request: Request):
        user = getattr(request.state, "user", None) or {}
        if user.get("role") != "admin":
            return JSONResponse({"error": "admin"}, status_code=403)
        return {"ok": True}

    @app.post("/isms")
    def isms_post(request: Request):
        user = getattr(request.state, "user", None) or {}
        if user.get("role") != "admin":
            return JSONResponse({"error": "admin"}, status_code=403)
        return {"ok": True}

    @app.post("/api/undo")
    def undo():
        return {"ok": True}

    @app.get("/red/report.pdf")
    def red_pdf():
        return JSONResponse({"ok": True})

    webguard.install(app, store_getter=lambda: store)
    return TestClient(app, base_url="https://testserver")


def _login_guest(store):
    webauth.bootstrap_admin(store)
    webauth.create_user(store, "Gast", "Gast", role="viewer")
    client = _app(store)
    r = client.post("/api/login", json={"username": "Gast", "password": "Gast"}, headers=ORIGIN)
    assert r.status_code == 200
    return client


def test_guest_allowed_and_forbidden_endpoints(hosted_env, tmp_path):
    from antbb.store import Store
    store = Store(str(tmp_path / "guest-allow.db"))
    client = _login_guest(store)

    allowed_get = [
        "/api/thing", "/api/targets", "/api/brain/logs", "/red/report.pdf",
    ]
    for path in allowed_get:
        r = client.get(path)
        assert r.status_code == 200, f"GET {path} -> {r.status_code}"

    allowed_post = [
        ("/api/targets/2/scan", {"active": False, "depth": "light"}),
        ("/api/targets/2/scan/cancel", {}),
        ("/api/blue/run", {"apply_fixes": False, "depth": "light"}),
        ("/osint/run", {"target_id": 2}),
        ("/yellow/upload", {}),
        ("/api/reports/generate", {}),
    ]
    for path, body in allowed_post:
        hosted.reset_guest_rate()
        r = client.post(path, json=body, headers=ORIGIN)
        assert r.status_code in (200, 202), f"POST {path} -> {r.status_code} {r.text}"

    forbidden = [
        ("/api/targets", {"name": "evil"}),
        ("/api/targets/2/scopes", {"kind": "url", "value": "https://example.com"}),
        ("/api/targets/2/oversight", {"confirmed": True}),
        ("/api/targets/2/mode", {"mode_policy": "offensive"}),
        ("/api/blue/findings/1/apply", {"oversight_ack": True}),
        ("/isms", {"org_name": "x"}),
        ("/api/undo", {}),
        ("/api/thing", {}),
    ]
    for path, body in forbidden:
        r = client.post(path, json=body, headers=ORIGIN)
        assert r.status_code == 403, f"forbidden POST {path} -> {r.status_code} {r.text}"

    r = client.delete("/api/targets/2/scopes/1", headers=ORIGIN)
    assert r.status_code == 403
    r = client.delete("/api/brain/logs", headers=ORIGIN)
    assert r.status_code == 403
    r = client.get("/isms")
    assert r.status_code == 403

    # Targeted cases required by the brief
    hosted.reset_guest_rate()
    r = client.post("/api/targets/2/scan",
                    json={"offensive": True, "oversight_ack": True, "depth": "light"},
                    headers=ORIGIN)
    assert r.status_code == 403, r.text
    assert "offen" in r.json()["error"].lower() or "Oversight" in r.json()["error"]

    r = client.post("/api/targets", json={"name": "gast-darf-nicht"}, headers=ORIGIN)
    assert r.status_code == 403


def test_admin_still_has_full_writes(hosted_env, tmp_path):
    from antbb.store import Store
    store = Store(str(tmp_path / "guest-admin.db"))
    webauth.bootstrap_admin(store)
    client = _app(store)
    r = client.post("/api/login", json={"username": "admin", "password": PASSWORD}, headers=ORIGIN)
    assert r.status_code == 200
    assert client.post("/api/targets", json={"name": "ok"}, headers=ORIGIN).status_code == 200
    assert client.post("/api/targets/2/oversight", json={"confirmed": True}, headers=ORIGIN).status_code == 200
    assert client.get("/isms").status_code == 200
    assert client.post("/isms", json={"org_name": "x"}, headers=ORIGIN).status_code == 200


def test_guest_rate_limit_parallel_and_hourly(hosted_env, tmp_path):
    from antbb.store import Store
    store = Store(str(tmp_path / "guest-rate.db"))
    client = _login_guest(store)
    hosted.reset_guest_rate()
    r1 = client.post("/api/targets/2/scan", json={"depth": "light"}, headers=ORIGIN)
    assert r1.status_code in (200, 202)
    r2 = client.post("/api/targets/2/scan", json={"depth": "light"}, headers=ORIGIN)
    assert r2.status_code == 429, r2.text
    hosted.reset_guest_rate()
    codes = []
    for _ in range(hosted.GUEST_RUNS_PER_HOUR + 1):
        # release parallel so only the hourly cap fires
        hosted.reset_guest_rate() if False else None
        hosted.guest_rate_leave("Gast")
        hosted.guest_rate_leave("gast")
        codes.append(client.post("/osint/run", json={"target_id": 2}, headers=ORIGIN).status_code)
    # osint is sync so parallel is released after each request; hourly should trip
    # After reset above we leaked leaves. Do a clean hourly test:
    hosted.reset_guest_rate()
    codes = [client.post("/osint/run", json={"target_id": 2}, headers=ORIGIN).status_code
             for _ in range(hosted.GUEST_RUNS_PER_HOUR + 1)]
    assert codes[:hosted.GUEST_RUNS_PER_HOUR] == [200] * hosted.GUEST_RUNS_PER_HOUR
    assert codes[-1] == 429


def test_guest_csrf_still_required(hosted_env, tmp_path):
    from antbb.store import Store
    store = Store(str(tmp_path / "guest-csrf.db"))
    client = _login_guest(store)
    r = client.post("/api/targets/2/scan", json={"depth": "light"})
    assert r.status_code == 403
    assert "Cross-site" in r.json()["error"] or "cross-site" in r.json()["error"].lower()


def test_proof_label_marks_guest_runs():
    from antbb.isms_report import _proof_label
    lab = _proof_label({
        "queen": "red", "title": "Testdienst", "run_id": "run-1",
        "started_by": "Gast", "when": "10.11.2026 12:00 Europe/Berlin",
        "asset": "https://antbb.carescribe.online",
    })
    assert "gestartet von Gast" in lab
    assert "Testlauf" in lab
