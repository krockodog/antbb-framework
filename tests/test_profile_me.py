"""Profil-Seite, /api/me, Passwortaenderung und bootstrap_admin ohne
Ueberschreiben. TestClient, lokale Temp-DB, keine echten Ziele."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["ANTBB_NO_LLM"] = "1"


import pytest
from fastapi.testclient import TestClient

from antbb import totp, webauth
from antbb.store import Store

ADMIN_PW = "ProfileAdmin!Test-1"
NEW_PW = "Brand-New-Passw0rd!"


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTBB_AUTH", "1")
    monkeypatch.setenv("ANTBB_ADMIN_USER", "mark")
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("ANTBB_DATA", str(tmp_path))
    monkeypatch.delenv("ANTBB_HOSTED", raising=False)
    monkeypatch.delenv("ANTBB_ALERT_NTFY_URL", raising=False)
    monkeypatch.setenv("ANTBB_TOTP_KEY", "")
    totp.reset_cache()
    webauth.reset_login_throttle()
    from antbb.web.app import app, svc
    prev = svc.store
    svc.store = Store(str(tmp_path / "profile.db"))
    webauth.bootstrap_admin(svc.store)
    yield app, svc
    svc.store.close()
    svc.store = prev
    totp.reset_cache()
    webauth.reset_login_throttle()


def _client(app):
    c = TestClient(app, headers={"origin": "http://testserver"})
    c.follow_redirects = False
    return c


def _login(app, user, pw):
    c = _client(app)
    r = c.post("/login", data={"username": user, "password": pw, "next": "/"})
    assert r.status_code == 303, r.text
    return c


def test_api_me_requires_session(env):
    app, _ = env
    r = _client(app).get("/api/me")
    assert r.status_code == 401


def test_api_me_admin_and_member(env):
    app, svc = env
    admin = _login(app, "mark", ADMIN_PW)
    body = admin.get("/api/me").json()
    assert body == {"username": "mark", "role": "admin", "is_admin": True}
    webauth.create_user(svc.store, "member-one", "Member-One-Pass!", role="member")
    m = _login(app, "member-one", "Member-One-Pass!")
    body = m.get("/api/me").json()
    assert body == {"username": "member-one", "role": "member", "is_admin": False}
    assert "pw_hash" not in m.get("/api/me").text


def test_profile_page_and_redirect(env):
    app, svc = env
    assert _client(app).get("/profile").status_code == 303
    assert "/login" in _client(app).get("/profile").headers["location"]
    admin = _login(app, "mark", ADMIN_PW)
    page = admin.get("/profile")
    assert page.status_code == 200
    assert "mark" in page.text and "/profile/password" in page.text
    assert 'href="/admin/users"' in page.text
    assert "/profile/2fa/setup" in page.text  # 2FA bleibt erhalten
    assert admin.get("/profile/2fa").status_code == 200
    webauth.create_user(svc.store, "member-two", "Member-Two-Pass!", role="member")
    m = _login(app, "member-two", "Member-Two-Pass!")
    mp = m.get("/profile").text
    assert "/profile/password" in mp and 'href="/admin/users">→' not in mp


@pytest.mark.parametrize("role", ["member", "member_plus", "viewer", "guest_user"])
def test_admin_users_denied_for_non_admin(env, role):
    app, svc = env
    name = f"user-{role.replace('_', '-')}"
    webauth.create_user(svc.store, name, "Some-Long-Pass-1!", role=role)
    c = _login(app, name, "Some-Long-Pass-1!")
    assert c.get("/admin/users").status_code == 403
    assert c.get("/api/users").status_code == 403
    assert _login(app, "mark", ADMIN_PW).get("/admin/users").status_code == 200


def test_password_change_rejects_wrong_current(env):
    app, svc = env
    admin = _login(app, "mark", ADMIN_PW)
    r = admin.post("/profile/password", data={"current_password": "wrong-password!!",
                                              "new_password": NEW_PW, "new_password_confirm": NEW_PW})
    assert r.status_code == 400
    assert webauth.authenticate(svc.store, "mark", ADMIN_PW) is not None
    assert webauth.authenticate(svc.store, "mark", NEW_PW) is None


def test_password_change_rejects_short_and_mismatch(env):
    app, svc = env
    admin = _login(app, "mark", ADMIN_PW)
    r = admin.post("/profile/password", data={"current_password": ADMIN_PW,
                                              "new_password": "short-11ch", "new_password_confirm": "short-11ch"})
    assert r.status_code == 400
    r = admin.post("/profile/password", data={"current_password": ADMIN_PW,
                                              "new_password": NEW_PW, "new_password_confirm": NEW_PW + "x"})
    assert r.status_code == 400
    assert webauth.authenticate(svc.store, "mark", ADMIN_PW) is not None


def test_password_change_rate_limited(env, monkeypatch):
    app, _ = env
    monkeypatch.setenv("ANTBB_LOGIN_MAX_ATTEMPTS", "2")
    admin = _login(app, "mark", ADMIN_PW)
    data = {"current_password": "nope-nope-nope", "new_password": NEW_PW, "new_password_confirm": NEW_PW}
    assert admin.post("/profile/password", data=data).status_code == 400
    assert admin.post("/profile/password", data=data).status_code == 400
    assert admin.post("/profile/password", data=data).status_code == 429


def test_password_change_cross_site_rejected(env):
    app, svc = env
    admin = _login(app, "mark", ADMIN_PW)
    r = admin.post("/profile/password", headers={"origin": "https://evil.example"},
                   data={"current_password": ADMIN_PW, "new_password": NEW_PW,
                         "new_password_confirm": NEW_PW})
    assert r.status_code == 403
    assert webauth.authenticate(svc.store, "mark", ADMIN_PW) is not None


def test_password_change_success_revokes_other_sessions(env):
    app, svc = env
    other = _login(app, "mark", ADMIN_PW)
    current = _login(app, "mark", ADMIN_PW)
    assert other.get("/api/me").status_code == 200
    r = current.post("/profile/password", data={"current_password": ADMIN_PW,
                                                "new_password": NEW_PW, "new_password_confirm": NEW_PW})
    assert r.status_code == 200, r.text
    assert webauth.COOKIE_NAME in r.headers.get("set-cookie", "")
    # aktuelle Sitzung (neu ausgestellt) laeuft weiter, die andere ist beendet
    assert current.get("/api/me").status_code == 200
    assert other.get("/api/me").status_code == 401
    assert webauth.authenticate(svc.store, "mark", NEW_PW) is not None
    assert webauth.authenticate(svc.store, "mark", ADMIN_PW) is None
    _login(app, "mark", NEW_PW)


def test_bootstrap_does_not_overwrite_existing_password(env, monkeypatch):
    _, svc = env
    webauth.set_password(svc.store, "mark", NEW_PW)
    svc.store.set_user_role("mark", "member")
    assert webauth.bootstrap_admin(svc.store) == "mark"
    assert webauth.authenticate(svc.store, "mark", NEW_PW) is not None
    assert webauth.authenticate(svc.store, "mark", ADMIN_PW) is None
    assert svc.store.get_user("mark")["role"] == "admin"


def test_bootstrap_creates_missing_admin(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTBB_ADMIN_USER", "fresh-admin")
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.delenv("ANTBB_ADMIN_PASSWORD_HASH", raising=False)
    store = Store(str(tmp_path / "boot.db"))
    try:
        assert webauth.bootstrap_admin(store) == "fresh-admin"
        row = store.get_user("fresh-admin")
        assert row["role"] == "admin" and row["active"]
        assert webauth.authenticate(store, "fresh-admin", ADMIN_PW) is not None
    finally:
        store.close()
