"""Loopback bind, required login, CSRF, and the non-root guard."""
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from antbb import webauth
from antbb.netbind import (
    _WARNED,
    assert_not_root,
    assert_runtime_safe,
    bind_violation,
    expose_enabled,
    is_loopback,
    resolve_bind_host,
)
from antbb.webguard import _mode


class _FakeRequest:
    def __init__(self, host):
        self.scope = {"server": (host, 8000)}


def test_loopback_defaults_and_refuses_wildcard(monkeypatch, capsys):
    monkeypatch.delenv("ANTBB_EXPOSE", raising=False)
    monkeypatch.delenv("YQ_EXPOSE", raising=False)
    for name in ("ANTBB_HOST", "ANTBB_WEB_HOST", "ALLONE_HOST", "YQ_HOST"):
        monkeypatch.delenv(name, raising=False)
    assert expose_enabled() is False
    assert resolve_bind_host(None) == "127.0.0.1"
    assert resolve_bind_host("localhost") == "127.0.0.1"
    assert is_loopback("127.0.0.1")
    assert bind_violation("testserver") is None
    assert bind_violation("127.0.0.1") is None
    with pytest.raises(SystemExit) as unset:
        resolve_bind_host("0.0.0.0")
    assert "ANTBB_EXPOSE is 0 (default)" in str(unset.value)
    assert "0.0.0.0" in str(unset.value)
    assert "ANTBB_EXPOSE=1" in str(unset.value)
    refused = bind_violation("0.0.0.0")
    assert refused and "ANTBB_EXPOSE is 0 (default)" in refused
    assert "0.0.0.0" in refused

    monkeypatch.setenv("ANTBB_EXPOSE", "0")
    assert expose_enabled() is False
    with pytest.raises(SystemExit) as zero:
        resolve_bind_host("10.0.0.5")
    assert "ANTBB_EXPOSE is 0 (default)" in str(zero.value)
    assert "10.0.0.5" in str(zero.value)
    for off in ("false", "no", "off", ""):
        monkeypatch.setenv("ANTBB_EXPOSE", off)
        assert expose_enabled() is False

    _WARNED.clear()
    for on in ("1", "true", "yes", "on"):
        monkeypatch.setenv("ANTBB_EXPOSE", on)
        assert expose_enabled() is True
    monkeypatch.setenv("ANTBB_EXPOSE", "1")
    assert resolve_bind_host("0.0.0.0") == "0.0.0.0"
    warning = capsys.readouterr().err
    assert "ANTBB_EXPOSE is 1" in warning
    assert "0.0.0.0" in warning
    assert "SSH tunnel" in warning
    assert bind_violation("192.168.1.5") is None


def test_real_socket_without_credentials_is_closed(monkeypatch):
    monkeypatch.delenv("ANTBB_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("ANTBB_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("ANTBB_AUTH", raising=False)
    assert _mode(_FakeRequest("testserver")) == "off"
    assert _mode(_FakeRequest("127.0.0.1")) == "unconfigured"


def test_refuses_root_and_missing_credential(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.delenv("ANTBB_ALLOW_ROOT", raising=False)
    with pytest.raises(SystemExit):
        assert_not_root()
    monkeypatch.setenv("ANTBB_ALLOW_ROOT", "1")
    assert_not_root()
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.delenv("ANTBB_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("ANTBB_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("ANTBB_TESTING", raising=False)
    monkeypatch.delenv("ANTBB_EXPOSE", raising=False)
    with pytest.raises(SystemExit):
        assert_runtime_safe("127.0.0.1")


def test_password_hash_roundtrip_and_constant_work(tmp_path):
    from antbb.store import Store

    encoded = webauth.format_password_hash("correct-horse")
    parsed = webauth.parse_password_hash(encoded)
    assert parsed is not None
    digest, salt, iterations = parsed
    assert webauth.verify_password("correct-horse", digest, salt, iterations)
    assert webauth.parse_password_hash(encoded.replace(":", "$")) == parsed
    store = Store(str(tmp_path / "users.sqlite"))
    try:
        assert webauth.authenticate(store, "nobody", "x") is None
    finally:
        store.close()


def test_login_cookie_csrf_and_rate_limit(monkeypatch, tmp_path):
    db = tmp_path / "auth.sqlite"
    monkeypatch.setenv("ANTBB_DB", str(db))
    monkeypatch.setenv("ANTBB_ADMIN_USER", "admin")
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD", "correct-horse")
    monkeypatch.setenv("ANTBB_LOGIN_MAX_ATTEMPTS", "3")
    monkeypatch.delenv("ANTBB_AUTH", raising=False)
    webauth.reset_login_throttle()

    from antbb.store import Store
    from antbb.web.app import app
    from antbb.web import app as web_app
    from antbb import webguard

    previous = web_app.svc.store
    previous_getter = webguard._GETTER
    web_app.svc.store = Store(str(db))
    try:
        _exercise_login(app, web_app, webguard, monkeypatch)
    finally:
        web_app.svc.store.close()
        web_app.svc.store = previous
        webguard._GETTER = previous_getter
        webauth.reset_login_throttle()


def _exercise_login(app, web_app, webguard, monkeypatch):
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/targets").status_code == 401
        page = client.get("/login")
        assert page.status_code == 200
        assert "password" in page.text.lower()

        bad = client.post(
            "/login",
            data={"username": "admin", "password": "nope", "next": "/"},
            follow_redirects=False,
        )
        assert bad.status_code in (302, 303, 401)

        ok = client.post(
            "/login",
            data={"username": "admin", "password": "correct-horse", "next": "/"},
            follow_redirects=False,
        )
        assert ok.status_code in (302, 303)
        cookie = " ".join(ok.headers.get_list("set-cookie")).lower()
        assert "httponly" in cookie
        assert "samesite=lax" in cookie
        assert webauth.COOKIE_NAME in cookie

        client.cookies.set(webauth.COOKIE_NAME, ok.cookies.get(webauth.COOKIE_NAME))
        assert client.get("/api/targets").status_code == 200
        crossed = client.post(
            "/api/reports/generate",
            json={"queen": "green"},
            headers={"Origin": "https://evil.example"},
        )
        assert crossed.status_code == 403

    api = FastAPI()

    @api.get("/api/secret")
    def secret():
        return {"ok": True}

    webguard.install(api, lambda: web_app.svc.store)
    with TestClient(api) as other:
        token = other.post(
            "/api/login",
            json={"username": "admin", "password": "correct-horse"},
        ).json()["token"]
    with TestClient(api) as bare:
        assert bare.get("/api/secret").status_code == 401
        allowed = bare.get("/api/secret", headers={"Authorization": f"Bearer {token}"})
        assert allowed.status_code == 200

    webauth.reset_login_throttle()
    monkeypatch.setenv("ANTBB_LOGIN_MAX_ATTEMPTS", "2")
    with TestClient(app) as client:
        for _ in range(2):
            client.post("/api/login", json={"username": "admin", "password": "wrong"})
        limited = client.post("/api/login", json={"username": "admin", "password": "correct-horse"})
        assert limited.status_code == 429
