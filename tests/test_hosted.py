"""Hosted mode (ANTBB_HOSTED=1): fail closed, headers, cookies, CSRF, gates."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from antbb import hosted, webauth, webguard

PASSWORD = "testserver-password-only"


@pytest.fixture
def hosted_env(monkeypatch, tmp_path):
    for name in ("ANTBB_ADMIN_PASSWORD", "ANTBB_TESTING", "ANTBB_EXPOSE", "YQ_EXPOSE",
                 "ANTBB_AUTH", "ANTBB_COOKIE_SECURE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTBB_HOSTED", "1")
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD_HASH", webauth.format_password_hash(PASSWORD))
    monkeypatch.setenv("ANTBB_DB", str(tmp_path / "hosted.db"))
    webauth.reset_login_throttle()
    yield
    webauth.reset_login_throttle()


def _client():
    from antbb.store import Store

    store = Store()
    webauth.bootstrap_admin(store)
    app = FastAPI()

    @app.get("/api/thing")
    def thing():
        return {"ok": True}

    @app.post("/api/thing")
    def post_thing():
        return {"ok": True}

    webguard.install(app, store_getter=lambda: store)
    return TestClient(app, base_url="https://testserver")


def test_readiness_fails_closed(monkeypatch, hosted_env):
    assert hosted.readiness_error() is None
    monkeypatch.delenv("ANTBB_ADMIN_PASSWORD_HASH")
    assert "requires ANTBB_ADMIN_PASSWORD_HASH" in hosted.readiness_error()
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD", "plain")
    assert hosted.readiness_error()  # plaintext alone is not enough
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD_HASH", webauth.format_password_hash(PASSWORD))
    assert "plaintext" in hosted.readiness_error()
    monkeypatch.delenv("ANTBB_ADMIN_PASSWORD")
    monkeypatch.setenv("ANTBB_EXPOSE", "1")
    assert "ANTBB_EXPOSE" in hosted.readiness_error()
    with pytest.raises(SystemExit):
        hosted.assert_ready()


def test_weak_hash_refused(monkeypatch, hosted_env):
    digest, salt, _ = webauth.hash_password(PASSWORD, iterations=20000)
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD_HASH", f"pbkdf2_sha256:20000:{salt}:{digest}")
    assert "iterations" in hosted.readiness_error()


def test_unauthenticated_is_blocked_with_headers(hosted_env):
    client = _client()
    assert client.get("/healthz").status_code == 200
    response = client.get("/api/thing")
    assert response.status_code == 401
    for header in ("content-security-policy", "strict-transport-security", "x-frame-options",
                   "x-content-type-options", "referrer-policy"):
        assert header in response.headers
    page = client.get("/anything", headers={"accept": "text/html"}, follow_redirects=False)
    assert page.status_code in (302, 303)
    assert client.get("/openapi.json").status_code in (401, 404)


def test_login_cookie_flags_and_csrf(hosted_env):
    client = _client()
    origin = {"origin": "https://testserver"}
    login = client.post("/api/login", json={"username": "admin", "password": PASSWORD}, headers=origin)
    assert login.status_code == 200
    cookie = login.headers.get("set-cookie", "").lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert client.get("/api/thing").status_code == 200
    assert client.post("/api/thing", headers=origin).status_code == 200
    assert client.post("/api/thing").status_code == 403  # no origin, no token
    assert client.post("/api/thing", headers={"origin": "https://evil.example"}).status_code == 403


def test_login_rate_limit(monkeypatch, hosted_env):
    monkeypatch.setenv("ANTBB_LOGIN_MAX_ATTEMPTS", "3")
    client = _client()
    origin = {"origin": "https://testserver"}
    codes = [client.post("/api/login", json={"username": "admin", "password": "wrong"},
                         headers=origin).status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401]
    assert codes[-1] == 429
    # The right password is still refused while the budget is used up.
    assert client.post("/api/login", json={"username": "admin", "password": PASSWORD},
                       headers=origin).status_code == 429


def test_scan_gates_server_side(hosted_env):
    from antbb.oversight import OversightError
    from antbb.service import AntBBService as Service

    svc = Service()
    tid = svc.add_target("hosted-gate-test")
    with pytest.raises(OversightError):
        svc.run_scan(tid)
    svc.set_oversight(tid, True)
    with pytest.raises(OversightError, match="Scope"):
        svc.run_scan(tid)
    with pytest.raises(OversightError):
        svc.run_blue(apply_fixes=True)
