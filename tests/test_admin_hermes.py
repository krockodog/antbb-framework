"""/admin/hermes: nur Admin + aktiver Grant, Key nie im Browser, Router
waehlt hermes nie automatisch. TestClient + Temp-DB, Hermes per Monkeypatch."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["ANTBB_NO_LLM"] = "1"

import pytest
from fastapi.testclient import TestClient

from antbb import totp, webauth
from antbb.store import Store

ADMIN_PW = "Hermes-Admin!Test-1"
MP_PW = "Hermes-MemberPlus-1!"
FAKE_KEY = "test-key-" + "x" * 40


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTBB_AUTH", "1")
    monkeypatch.setenv("ANTBB_ADMIN_USER", "mark")
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("ANTBB_DATA", str(tmp_path))
    monkeypatch.delenv("ANTBB_HOSTED", raising=False)
    monkeypatch.delenv("HERMES_API_KEY", raising=False)
    monkeypatch.setenv("ANTBB_TOTP_KEY", "")
    keyfile = tmp_path / "hermes_api.key"
    keyfile.write_text(FAKE_KEY + "\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_API_KEY_FILE", str(keyfile))
    totp.reset_cache()
    webauth.reset_login_throttle()
    from antbb.web.app import app, svc
    prev = svc.store
    svc.store = Store(str(tmp_path / "hermes.db"))
    webauth.bootstrap_admin(svc.store)
    webauth.create_user(svc.store, "Bugbounty", MP_PW, role="member_plus")
    sent = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return {"status": "completed", "output": [
                {"type": "function_call", "name": "terminal", "arguments": "{\"command\": \"uptime\"}"},
                {"type": "function_call_output", "output": "up 1 day"},
                {"type": "message", "content": [{"type": "output_text", "text": "Antwort ok"}]}]}

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            sent.update(url=url, headers=headers, json=json)
            return FakeResp()

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    yield app, svc, sent
    svc.store.close()
    svc.store = prev
    totp.reset_cache()
    webauth.reset_login_throttle()


def _login(app, user, pw):
    c = TestClient(app, headers={"origin": "http://testserver"})
    c.follow_redirects = False
    assert c.post("/login", data={"username": user, "password": pw, "next": "/"}).status_code == 303
    return c


def test_key_from_file_and_router_skips_hermes(env):
    from antbb import llm, router
    assert llm.is_configured("hermes")
    assert "hermes" not in router._available()


def test_admin_needs_grant_then_chat(env):
    app, _, sent = env
    admin = _login(app, "mark", ADMIN_PW)
    page = admin.get("/admin/hermes")
    assert page.status_code == 200 and "Hermes-Chat" in page.text
    assert FAKE_KEY not in page.text and "hermes_api.key" not in page.text
    r = admin.post("/api/admin/hermes/chat", json={"message": "hallo"})
    assert r.status_code == 403
    g = admin.post("/api/admin/hermes/grant", json={"minutes": 30}).json()
    assert g["active"] and g["seconds_left"] > 1700
    r = admin.post("/api/admin/hermes/chat", json={"message": "hallo"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["reply"] == "Antwort ok" and d["tools"][0]["name"] == "terminal"
    assert FAKE_KEY not in r.text
    assert sent["url"] == "http://127.0.0.1:8642/v1/responses"
    assert sent["headers"]["Authorization"] == "Bearer " + FAKE_KEY
    assert sent["json"]["conversation"].startswith("antbb-mark-")
    assert admin.post("/api/admin/hermes/grant", json={"minutes": 0}).json()["active"] is False
    assert admin.post("/api/admin/hermes/chat", json={"message": "x"}).status_code == 403


def test_cross_site_post_rejected(env):
    app, _, _ = env
    admin = _login(app, "mark", ADMIN_PW)
    r = admin.post("/api/admin/hermes/grant", json={"minutes": 30},
                   headers={"origin": "https://evil.example"})
    assert r.status_code == 403


def test_member_plus_and_anonymous_blocked(env):
    app, _, sent = env
    mp = _login(app, "Bugbounty", MP_PW)
    for path in ("/admin/hermes", "/api/admin/hermes/grant"):
        r = mp.get(path)
        assert r.status_code == 403 and "8642" not in r.text and "hermes_api" not in r.text
    assert mp.post("/api/admin/hermes/grant", json={"minutes": 30}).status_code == 403
    assert mp.post("/api/admin/hermes/chat", json={"message": "x"}).status_code == 403
    for page in ("/red", "/profile"):
        assert "/admin/hermes" not in mp.get(page).text
    anon = TestClient(app)
    anon.follow_redirects = False
    assert anon.get("/admin/hermes").status_code in (303, 401)
    assert anon.post("/api/admin/hermes/chat", json={"message": "x"},
                     headers={"accept": "application/json"}).status_code in (401, 403)
    assert not sent
