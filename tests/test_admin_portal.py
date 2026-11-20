"""Admin-Portal: Rollen member/member_plus, Einladungen, Pro-User-Historie,
Alarme, 2FA (TOTP) und Kick. TestClient, lokale Temp-DB, keine echten Ziele."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["ANTBB_NO_LLM"] = "1"
os.environ.setdefault("ANTBB_DB", "/tmp/antbb_test_admin_portal_boot.db")

import pytest
from fastapi.testclient import TestClient

from antbb import hosted, totp, webauth, webguard
from antbb.store import Store

ADMIN_PW = "AdminPortal!Test-1"


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTBB_AUTH", "1")
    monkeypatch.setenv("ANTBB_ADMIN_USER", "Marc")
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("ANTBB_DATA", str(tmp_path))
    monkeypatch.delenv("ANTBB_HOSTED", raising=False)
    monkeypatch.delenv("ANTBB_ALERT_NTFY_URL", raising=False)
    monkeypatch.setenv("ANTBB_TOTP_KEY", "")
    totp.reset_cache()
    webauth.reset_login_throttle()
    from antbb.web.app import app, svc
    prev = svc.store
    svc.store = Store(str(tmp_path / "portal.db"))
    webauth.bootstrap_admin(svc.store)
    yield app, svc
    svc.store.close()
    svc.store = prev
    totp.reset_cache()


def _login(client, user, pw):
    r = client.post("/login", data={"username": user, "password": pw, "next": "/"})
    return r


def _client(app):
    c = TestClient(app, headers={"origin": "http://testserver"})
    c.follow_redirects = False
    return c


def _invite(admin, role, username=""):
    r = admin.post("/api/users/invite", json={"role": role, "username": username, "days": 1})
    assert r.status_code == 200, r.text
    return r.json()["url"].rsplit("/invite/", 1)[1]


def _accept(app, token, username, pw):
    c = _client(app)
    r = c.post(f"/invite/{token}", data={"username": username, "password": pw,
                                          "password_confirm": pw})
    assert r.status_code == 303, r.text
    return c


def test_roles_helpers():
    assert not hosted.is_guest("member") and not hosted.is_guest("member_plus")
    assert webauth.can_ops("member") and webauth.can_ops("member_plus") and webauth.can_ops("admin")
    assert not webauth.can_ops("viewer") and not webauth.can_ops("guest_user")
    assert webauth.can_wlan("member_plus") and not webauth.can_wlan("member")
    assert "member_plus" in webauth.ROLES and "member" in webauth.ROLES


def test_totp_rfc6238_vector():
    # RFC 6238 Anhang B, SHA1, T=59 -> 94287082 (8 Ziffern) -> letzte 6: 287082
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp.hotp(secret, 59 // 30) == "287082"
    step = totp.verify(secret, "287082", None, now=59)
    assert step == 1
    assert totp.verify(secret, "287082", step, now=59) is None  # Replay


def test_invite_member_flow_and_admin_only(env):
    app, svc = env
    admin = _client(app)
    assert _login(admin, "Marc", ADMIN_PW).status_code == 303
    assert admin.get("/admin/users").status_code == 200
    page = admin.get("/admin/users").text
    assert 'value="member_plus"' in page and 'value="member"' in page
    tok = _invite(admin, "member", "")
    assert admin.get(f"/invite/{tok}").status_code == 200
    m = _accept(app, tok, "member-test", "MemberTest!2026")
    assert svc.store.get_user("member-test")["role"] == "member"
    # Einmalig
    assert _client(app).post(f"/invite/{tok}", data={"username": "x-two", "password": "abcdefghijk",
                                                      "password_confirm": "abcdefghijk"}).status_code == 400
    assert m.get("/admin/users").status_code == 403
    assert m.get("/api/users").status_code == 403
    assert m.get("/api/admin/alerts/count").status_code == 403
    # member legt eigenes Ziel an und sieht Scope-Form
    r = m.post("/target/add", data={"name": "own-target", "description": "", "mode_policy": "offensive"})
    assert r.status_code == 303
    tid = int(r.headers["location"].rsplit("/", 1)[1])
    assert svc.store.target_owner(tid) == "member-test"
    assert svc.store.get_target(tid)["mode_policy"] == "auto"  # Policy bleibt admin-only
    html = m.get(f"/target/{tid}").text
    assert f"/target/{tid}/scope/add" in html and f"/target/{tid}/oversight" in html
    assert m.post(f"/target/{tid}/scope/add", data={"kind": "domain", "value": "127.0.0.1"}).status_code == 303
    assert m.post(f"/target/{tid}/oversight", data={"confirm": "on"}).status_code == 303
    assert m.post(f"/target/{tid}/mode", data={"mode_policy": "offensive"}).status_code == 403
    # Admin-Ziel ist fuer member tabu
    atid = svc.add_target("admin-target")
    assert m.get(f"/target/{atid}").status_code == 403
    # Alarm entstanden (admin_denied / owner_denied), member sieht ihn nicht
    assert svc.store.count_open_alerts() >= 1
    assert "alert-banner" not in m.get("/history").text
    assert "alert-banner" in admin.get("/history").text
    assert admin.get("/api/admin/alerts/count").json()["open"] >= 1


def test_history_separation(env):
    app, svc = env
    admin = _client(app)
    _login(admin, "Marc", ADMIN_PW)
    a = _accept(app, _invite(admin, "member"), "hist-a", "HistoryA!2026")
    b = _accept(app, _invite(admin, "member_plus"), "hist-b", "HistoryB!2026")
    ra = svc.store.add_run_history("run-a", None, "ta", owner_user="hist-a", started_by="hist-a")
    svc.store.add_run_history("run-b", None, "tb", owner_user="hist-b", started_by="hist-b")
    svc.store.add_run_history("run-legacy", None, "tl")
    ids_a = {r["run_id"] for r in a.get("/api/runs").json()}
    ids_b = {r["run_id"] for r in b.get("/api/runs").json()}
    ids_admin = {r["run_id"] for r in admin.get("/api/runs").json()}
    assert ids_a == {"run-a"} and ids_b == {"run-b"}
    assert {"run-a", "run-b", "run-legacy"} <= ids_admin
    assert b.get(f"/api/runs/{ra}/timeline").status_code == 404
    assert a.get(f"/api/runs/{ra}/timeline").status_code == 200
    assert "run-b" not in a.get("/history").text
    assert "ohne Zuordnung" in admin.get("/history").text or "unassigned" in admin.get("/history").text
    assert "tb" in admin.get("/history?user=hist-b").text
    assert a.get("/exports/x.pdf").status_code == 403


def test_2fa_and_kick(env):
    app, svc = env
    admin = _client(app)
    _login(admin, "Marc", ADMIN_PW)
    pw = "TwoFactor!2026x"
    u = _accept(app, _invite(admin, "member_plus"), "tfa-user", pw)
    assert u.post("/profile/2fa/setup").status_code == 200
    secret = totp.decrypt(svc.store.get_user("tfa-user")["totp_pending_enc"])
    page = u.post("/profile/2fa/confirm", data={"code": totp.totp(secret)})
    assert page.status_code == 200 and "Recovery" in page.text
    import re
    codes = re.findall(r"\b[0-9A-F]{5}-[0-9A-F]{5}\b", page.text)
    assert len(codes) == 8
    row = svc.store.get_user("tfa-user")
    assert row["totp_enabled"] == 1 and secret not in (row["totp_secret_enc"] or "")
    # Login zweistufig
    c = _client(app)
    r = _login(c, "tfa-user", pw)
    assert r.status_code == 303 and r.headers["location"].startswith("/login/2fa")
    assert c.post("/login/2fa", data={"code": "000000"}).headers["location"].startswith("/login/2fa")
    # Code wurde beim Bestaetigen schon benutzt -> Replay abgelehnt
    assert c.post("/login/2fa", data={"code": totp.totp(secret)}).headers["location"].startswith("/login/2fa")
    r = c.post("/login/2fa", data={"code": codes[0]})
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert c.get("/history").status_code == 200
    # Recovery-Code nur einmal
    c2 = _client(app)
    _login(c2, "tfa-user", pw)
    assert c2.post("/login/2fa", data={"code": codes[0]}).headers["location"].startswith("/login/2fa")
    # Kick waehrend aktiver Session
    assert admin.post("/admin/users/tfa-user/kick").status_code == 303
    r = c.get("/history")
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    c3 = _client(app)
    assert _login(c3, "tfa-user", pw).headers["location"].startswith("/login?error")
    # Self-Kick / letzter Admin
    r = admin.post("/admin/users/Marc/kick")
    assert "error=" in r.headers["location"]
    assert svc.store.get_user("Marc")["active"] == 1
    # Entsperren
    admin.post("/admin/users/tfa-user/unlock")
    assert svc.store.get_user("tfa-user")["active"] == 1
    # Admin-Reset 2FA
    admin.post("/admin/users/tfa-user/reset-2fa")
    assert svc.store.get_user("tfa-user")["totp_enabled"] == 0
    # Alarme quittieren
    assert admin.post("/admin/alerts/ack", data={"next": "/admin/alerts"}).status_code == 303
    assert admin.get("/api/admin/alerts/count").json()["open"] == 0


def test_wlan_gate_hosted(monkeypatch):
    monkeypatch.setenv("ANTBB_HOSTED", "1")

    class S:
        def target_owner(self, tid):
            return None

    assert webguard._role_gate(S(), {"role": "member", "username": "m"}, "/wlan", "GET")
    assert webguard._role_gate(S(), {"role": "member_plus", "username": "p"}, "/wlan", "GET") is None
    assert webguard._role_gate(S(), {"role": "member_plus", "username": "p"}, "/api/wlan/scan", "POST") is None
    assert webguard._role_gate(S(), {"role": "member", "username": "m"}, "/api/wlan/scan", "POST")
