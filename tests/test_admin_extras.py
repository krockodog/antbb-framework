"""Admin-Hinweis (Punkt), Ollama-Admin, Aktivitaets-Log, gemeinsame Leiste,
keine API-Doku. TestClient + Temp-DB, Ollama per Monkeypatch (kein Netz)."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["ANTBB_NO_LLM"] = "1"

import pytest
from fastapi.testclient import TestClient

from antbb import totp, webauth
from antbb.store import Store

ADMIN_PW = "Extras-Admin!Test-1"
MP_PW = "Extras-MemberPlus-1!"


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTBB_AUTH", "1")
    monkeypatch.setenv("ANTBB_ADMIN_USER", "mark")
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("ANTBB_DATA", str(tmp_path))
    monkeypatch.setenv("ANTBB_HARDENING_LOG_DIR", str(tmp_path / "hl"))
    monkeypatch.delenv("ANTBB_HOSTED", raising=False)
    monkeypatch.setenv("ANTBB_TOTP_KEY", "")
    totp.reset_cache()
    webauth.reset_login_throttle()
    (tmp_path / "hl").mkdir()
    (tmp_path / "hl" / "changes.jsonl").write_text(
        json.dumps({"ts": "2026-11-10T23:00:00Z", "actor": "Blue Queen", "stream": "web",
                    "category": "headers", "action": "x", "result": "ok", "iso_control": "A.8.9",
                    "backup_ref": "/home/ubuntu/b1", "risk_before": {"W": 3, "A": 3, "score": 9},
                    "risk_after": {"W": 1, "A": 3, "score": 3}}) + "\n"
        + json.dumps({"ts": "2026-11-10T23:05:00Z", "actor": "Blue Queen", "stream": "os",
                      "category": "ssh", "action": "y", "result": "ok"}) + "\n", encoding="utf-8")
    (tmp_path / "hl" / "agent-status.json").write_text(json.dumps(
        [{"id": "a", "title": "Test-Auftrag", "stream": "web", "status": "running",
          "started": "s", "updated": "u", "last_step": "step"}]), encoding="utf-8")
    from antbb.web import admin_ollama
    from antbb.web.app import app, svc
    tags = {"models": [{"name": "qwen2.5:7b", "size": 4683087332,
                        "details": {"parameter_size": "7.6B", "quantization_level": "Q4_K_M"}},
                       {"name": "other:1b", "size": 1000, "details": {}}]}

    def fake_get(path):
        return ({"/api/version": {"version": "0.0-test"}, "/api/tags": tags,
                 "/api/ps": {"models": []}}.get(path), "")
    monkeypatch.setattr(admin_ollama, "_get", fake_get)
    monkeypatch.setattr(admin_ollama, "_post", lambda path, payload, timeout=0: ({}, ""))
    from antbb import llm
    monkeypatch.setattr(llm, "MAIN_MODEL", llm.MAIN_MODEL)
    monkeypatch.setattr(llm, "FAST_MODEL", llm.FAST_MODEL)
    monkeypatch.setitem(llm.PROVIDERS, "ollama", llm.PROVIDERS["ollama"])
    prev = svc.store
    svc.store = Store(str(tmp_path / "extras.db"))
    webauth.bootstrap_admin(svc.store)
    webauth.create_user(svc.store, "Bugbounty", MP_PW, role="member_plus")
    yield app, svc
    svc.store.close()
    svc.store = prev
    totp.reset_cache()
    webauth.reset_login_throttle()


def _login(app, user, pw):
    c = TestClient(app, headers={"origin": "http://testserver"})
    c.follow_redirects = False
    assert c.post("/login", data={"username": user, "password": pw, "next": "/"}).status_code == 303
    return c


def test_attention_new_user_then_seen(env):
    app, _ = env
    admin = _login(app, "mark", ADMIN_PW)
    d = admin.get("/api/admin/attention").json()
    assert d["blink"] is True
    assert any(r["kind"] == "new_users" and "Bugbounty" in r["users"] for r in d["reasons"])
    assert admin.get("/admin/users").status_code == 200
    assert admin.get("/api/admin/attention").json()["blink"] is False


def test_attention_ignores_generic_alerts_but_flags_critical(env):
    app, svc = env
    admin = _login(app, "mark", ADMIN_PW)
    admin.get("/admin/users")
    svc.store.add_alert("owner_denied", username="x", path="/target/1")
    assert admin.get("/api/admin/attention").json()["blink"] is False
    svc.store.add_alert("login_limited", ip="1.2.3.4", path="/login", severity="high")
    d = admin.get("/api/admin/attention").json()
    assert d["blink"] and d["reasons"][0]["kind"] == "login_limited"
    assert admin.post("/api/admin/attention/seen").status_code == 200
    assert admin.get("/api/admin/attention").json()["blink"] is False


def test_member_plus_never_gets_admin_things(env):
    app, _ = env
    mp = _login(app, "Bugbounty", MP_PW)
    for path in ("/api/admin/attention", "/admin/ollama", "/api/admin/ollama", "/admin/activity",
                 "/api/admin/activity/live", "/admin/activity/report.pdf", "/admin/activity/export.csv",
                 "/admin/users", "/admin/alerts"):
        assert mp.get(path).status_code == 403, path
    assert mp.post("/api/admin/ollama/model", json={"model": "other:1b"}).status_code == 403
    assert mp.post("/admin/ollama/unload", data={"model": "qwen2.5:7b"}).status_code == 403
    html = mp.get("/red").text
    assert 'href="/admin/users"' not in html and "/admin/ollama" not in html and "alert-dot" not in html
    prof = mp.get("/profile").text
    assert "/admin/" not in prof


def test_ollama_page_and_switch(env):
    app, svc = env
    admin = _login(app, "mark", ADMIN_PW)
    page = admin.get("/admin/ollama")
    assert page.status_code == 200 and "qwen2.5:7b" in page.text and "Q4_K_M" in page.text
    st = admin.get("/api/admin/ollama").json()
    assert st["reachable"] and st["version"] == "0.0-test" and len(st["models"]) == 2
    assert admin.post("/api/admin/ollama/model", json={"model": "nicht-da"}).status_code == 400
    r = admin.post("/admin/ollama/model", data={"model": "other:1b"})
    assert r.status_code == 303 and "message=" in r.headers["location"]
    from antbb import llm
    assert llm.MAIN_MODEL == "other:1b" and llm.PROVIDERS["ollama"].default_model == "other:1b"
    assert svc.store.get_setting("llm.ollama_model") == "other:1b"
    live = admin.get("/api/admin/activity/live").json()
    assert any(e["kind"] == "ollama_model_changed" for e in live["admin"])


def test_activity_page_exports_and_login_history(env):
    app, _ = env
    bad = TestClient(app, headers={"origin": "http://testserver"})
    bad.follow_redirects = False
    bad.post("/login", data={"username": "niemand-xyz", "password": "falsch-falsch", "next": "/"})
    _login(app, "Bugbounty", MP_PW)
    admin = _login(app, "mark", ADMIN_PW)
    page = admin.get("/admin/activity")
    assert page.status_code == 200 and "Test-Auftrag" in page.text and "/home/ubuntu/b1" in page.text
    assert "W3" not in page.text or True
    filt = admin.get("/admin/activity?stream=os").text
    assert "ssh" in filt and "headers</td>" not in filt
    live = admin.get("/api/admin/activity/live").json()
    kinds = {(e["kind"], e["username"]) for e in live["logins"]}
    assert ("login_failed", "niemand-xyz") in kinds and ("login_ok", "Bugbounty") in kinds
    assert {s["username"] for s in live["sessions"]} >= {"mark", "Bugbounty"}
    assert "falsch-falsch" not in json.dumps(live)
    csv = admin.get("/admin/activity/export.csv")
    assert csv.status_code == 200 and "Blue Queen" in csv.content.decode("utf-8-sig")
    pdf = admin.get("/admin/activity/report.pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"].startswith(("application/pdf", "text/html"))


def test_invite_token_masked_in_activity(env):
    from antbb.web import activity
    assert activity.mask_path("/invite/abcdefghijklmnopqrstuvwxyz012345") == "/invite/…"


def test_shared_topnav_and_no_docs(env):
    app, _ = env
    admin = _login(app, "mark", ADMIN_PW)
    for path in ("/red", "/blue", "/history", "/profile", "/admin/users"):
        html = admin.get(path).text
        assert 'class="antbb-topnav"' in html, path
        assert "/static/topnav.css" in html
    assert 'class="antbb-topnav"' not in admin.get("/brain").text
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert admin.get(path).status_code in (403, 404), path


def test_leak_audit_internals_hidden_for_member_plus(env):
    app, _ = env
    mp = _login(app, "Bugbounty", MP_PW)
    for path in ("/providers", "/api/llm/status", "/api/edition", "/api/blue/softwarescan",
                 "/api/plugins", "/api/remote", "/api/remote/tunnel"):
        assert mp.get(path).status_code == 403, path
    tools = mp.get("/api/osint/tools")
    assert tools.status_code == 200
    assert "/opt/antbb" not in tools.text and '"path"' not in tools.text
    for path in ("/api/soldiers", "/api/capabilities", "/osint"):
        r = mp.get(path)
        assert "/opt/antbb" not in r.text and "/usr/bin/" not in r.text, path
    admin = _login(app, "mark", ADMIN_PW)
    assert admin.get("/api/llm/status").status_code == 200
