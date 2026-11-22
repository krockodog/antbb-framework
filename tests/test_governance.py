"""Governance: Risikoklassen, Scope-Policy-Gate (nur verschärfend), Audit, Kill Switch."""
import os
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("ANTBB_NO_LLM", "1")
os.environ.pop("ANTBB_AUTH", None)
os.environ.setdefault("ANTBB_DB", "/tmp/antbb_test_governance.db")

import pytest
from fastapi.testclient import TestClient

from antbb import governance as gov
from antbb import webauth
from antbb.store import Store
from antbb.web import app as webapp

# Eigenes Test-Admin-Konto (nie ein echtes Secret aus der Umgebung).
ADMIN_USER = "gov-test-admin"
ADMIN_PW = "GovTest!Admin-1"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTBB_HOSTED", raising=False)
    monkeypatch.setenv("ANTBB_TESTING", "1")
    # Auth wie in Produktion: eingeloggter Admin, isolierte Temp-DB pro Test.
    # Echte Zugangsdaten aus der Umgebung werden für den Test überschrieben.
    monkeypatch.setenv("ANTBB_AUTH", "1")
    monkeypatch.setenv("ANTBB_ADMIN_USER", ADMIN_USER)
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.delenv("ANTBB_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.setenv("ANTBB_DATA", str(tmp_path))
    monkeypatch.setenv("ANTBB_TOTP_KEY", "")
    webauth.reset_login_throttle()
    prev_store = webapp.svc.store
    webapp.svc.store = Store(str(tmp_path / "governance.db"))
    webauth.bootstrap_admin(webapp.svc.store)
    started = threading.Event()

    def fake_run_scan(target_id, emit=None, **kw):
        started.set()
        for _ in range(200):  # läuft bis Abbruch (max ~4 s)
            emit({"ts": time.time(), "msg": "tick"})
            time.sleep(0.02)
        raise RuntimeError("not cancelled")

    monkeypatch.setattr(webapp.svc, "run_scan", fake_run_scan)
    try:
        with TestClient(webapp.app, headers={"origin": "http://testserver"}) as c:
            r = c.post("/login", data={"username": ADMIN_USER, "password": ADMIN_PW,
                                       "next": "/"}, follow_redirects=False)
            assert r.status_code in (302, 303), r.text
            c.started = started
            yield c
        st = webapp.svc.store
        gov.reset_kill(st, actor="test", role="admin")
        for _ in range(100):
            if webapp.SCAN_STATE.get("status") != "running":
                break
            webapp.SCAN_STATE["cancel_requested"] = True
            time.sleep(0.05)
    finally:
        webapp.svc.store.close()
        webapp.svc.store = prev_store
        webauth.reset_login_throttle()


def _target(client, mode="auto"):
    name = f"gov-{uuid.uuid4().hex[:8]}.example"
    tid = client.post("/api/targets", json={"name": name, "mode_policy": mode}).json()["id"]
    client.post(f"/api/targets/{tid}/scopes", json={"kind": "domain", "value": name})
    client.post(f"/api/targets/{tid}/oversight", json={"confirmed": True, "by": "test"})
    return tid, name


def _wait_idle():
    for _ in range(200):
        if webapp.SCAN_STATE.get("status") != "running":
            return
        time.sleep(0.03)


def test_risk_classes_and_playbooks():
    assert [r["level"] for r in gov.RISK_TABLE] == ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert gov.playbook_risk("red", "dos-attack-x") == "CRITICAL"
    assert gov.playbook_risk("red", "verify-befund") == "HIGH"
    assert gov.playbook_risk("red", "unknown-new") == "HIGH"  # fail-safe
    assert gov.playbook_risk("red", "extras-osint") == "SAFE"
    assert gov.classify_scan(depth="light", engaged=False)[0] == "MEDIUM"
    assert gov.classify_scan(depth="light", engaged=True)[0] == "HIGH"


def test_policy_migrated_defaults_and_validation(client):
    tid, name = _target(client, "defensive")
    pol = client.get(f"/api/targets/{tid}/policy").json()
    assert name in pol["target_domains"]
    assert "HIGH" in pol["approval_required_for"]
    assert "vuln_validation" not in pol["allowed_techniques"]
    r = client.put(f"/api/targets/{tid}/policy", json={"allowed_techniques": ["destructive"]})
    assert r.status_code == 400
    r = client.put(f"/api/targets/{tid}/policy", json={"approval_required_for": []})
    assert r.status_code == 200 and "HIGH" in r.json()["approval_required_for"]


def test_gate_technique_and_window(client):
    tid, _ = _target(client)
    client.put(f"/api/targets/{tid}/policy", json={"allowed_techniques": ["dns", "tls"]})
    r = client.post(f"/api/targets/{tid}/scan", json={})
    assert r.status_code == 403 and "Technik" in r.json()["detail"]
    client.put(f"/api/targets/{tid}/policy", json={
        "allowed_techniques": gov.DEFAULT_TECHNIQUES_DEFENSIVE,
        "test_window_start": "2099-01-01T00:00"})
    r = client.post(f"/api/targets/{tid}/scan", json={})
    assert r.status_code == 403 and "Testfenster" in r.json()["detail"]
    entries = client.get("/api/governance/audit?limit=5").json()["entries"]
    assert entries[0]["result"] == "denied" and entries[0]["risk"] == "MEDIUM"


def test_offensive_without_oversight_still_403(client):
    tid, _ = _target(client, "offensive")
    r = client.post(f"/api/targets/{tid}/scan", json={"offensive": True})
    assert r.status_code == 403


def test_kill_switch_stops_and_blocks_then_reset(client):
    tid, _ = _target(client)
    r = client.post(f"/api/targets/{tid}/scan", json={})
    assert r.status_code == 200, r.text
    assert client.started.wait(3)
    assert client.post("/api/governance/kill", json={}).status_code == 400  # Bestätigung
    r = client.post("/api/governance/kill", json={"confirm": "STOP"})
    assert r.status_code == 200 and r.json()["stopped"]
    _wait_idle()
    assert webapp.SCAN_STATE["status"] == "cancelled"
    r = client.post(f"/api/targets/{tid}/scan", json={})
    assert r.status_code == 423
    st = client.get("/api/governance/status").json()
    assert st["kill_switch"]["state"] == "active"
    r = client.post("/api/governance/reset", json={"confirm": "RESET"})
    assert r.status_code == 200
    assert client.get("/api/governance/status").json()["kill_switch"]["state"] == "ready"
    actions = [e["action"] for e in client.get("/api/governance/audit?limit=10").json()["entries"]]
    assert "STOP ALL AGENTS" in actions and "Kill Switch zurückgesetzt" in actions


def test_status_shape(client):
    _target(client)
    st = client.get("/api/governance/status").json()
    for key in ("policy", "scope", "approval", "audit", "kill_switch", "risk_table"):
        assert key in st
    assert st["policy"]["label"] == "DEFAULT-DENY"


def test_select_all_batch_overrides_persist(client):
    reg = client.get("/api/capabilities").json()
    sol = next(s for s in reg["soldiers"] if s.get("colony") != "blue" and s.get("playbooks"))
    items = [{"soldier": sol["name"], "playbook": pb["name"],
              "key": f"task:{pb['name']}:{ti['task']}", "value": "done"}
             for pb in sol["playbooks"] for ti in pb.get("task_items", [])]
    assert items
    r = client.post("/api/soldiers/overrides/batch", json={"items": items})
    assert r.status_code == 200 and r.json()["saved"] == len(items)
    det = client.get(f"/api/soldiers/{sol['name']}").json()
    ov = {(o["playbook"], o["key"]): o["value"] for o in det.get("overrides", [])}
    assert all(ov.get((i["playbook"], i["key"])) == "done" for i in items)
    for i in items:
        i["value"] = "offen"
    assert client.post("/api/soldiers/overrides/batch", json={"items": items}).status_code == 200
    det = client.get(f"/api/soldiers/{sol['name']}").json()
    ov = {(o["playbook"], o["key"]): o["value"] for o in det.get("overrides", [])}
    assert all(ov.get((i["playbook"], i["key"])) == "offen" for i in items)
    # nur Aufgaben-Haken, kein "enabled"/Gate-Schlüssel über den Batch
    bad = [{"soldier": sol["name"], "playbook": "", "key": "enabled", "value": "done"}]
    assert client.post("/api/soldiers/overrides/batch", json={"items": bad}).status_code == 400
    # Haken ändern nichts am Gate: offensiv ohne Oversight bleibt 403
    tid, _ = _target(client, "offensive")
    assert client.post(f"/api/targets/{tid}/scan", json={"offensive": True}).status_code == 403


def test_role_permissions_scope_and_killswitch():
    """Task 4/5: member_plus darf Scopes autorisieren + Kill Switch + Reset;
    member nicht; User-/Rollenverwaltung bleibt admin."""
    import types
    from antbb import webauth
    from antbb.web import governance_routes as gr
    from antbb import governance as gov

    # Reine Rollenlogik
    assert webauth.can_authorize_scope("admin")
    assert webauth.can_authorize_scope("member_plus")
    assert not webauth.can_authorize_scope("member")
    assert not webauth.can_authorize_scope("viewer")

    def req(role):
        r = types.SimpleNamespace()
        r.state = types.SimpleNamespace(user={"username": "u", "role": role})
        return r

    # Kill Switch: admin + member_plus ja, member/viewer nein
    assert gr._can_kill(req("admin"))
    assert gr._can_kill(req("member_plus"))
    assert not gr._can_kill(req("member"))
    assert not gr._can_kill(req("viewer"))

    # Startseiten-Scope-Status: can_kill-Flag spiegelt die Rolle
    assert gov.status(user={"role": "member_plus"})["viewer"]["can_kill"] is True
    assert gov.status(user={"role": "member"})["viewer"]["can_kill"] is False
    assert gov.status(user={"role": "admin"})["viewer"]["can_kill"] is True


def test_kill_switch_blocks_remediate_recheck_then_reset(client, monkeypatch):
    """Kill Switch aktiv -> remediate-recheck wird an der Startprüfung hart
    geblockt (423, Service wird NICHT aufgerufen). Nach Reset läuft der Pfad
    wieder normal durch die üblichen Gates (Oversight-Gate bleibt wirksam)."""
    from antbb import remediation
    monkeypatch.setattr(remediation, "llm_suggest_remediation",
                        lambda finding, svc=None, max_retries=1: {"ok": True})
    tid, name = _target(client)
    st = webapp.svc.store
    fid = st.add_finding(target_id=tid, run_id="run-ks-1", agent="scanning",
                         title="Fehlender Security-Header: strict-transport-security",
                         category="misconfig", severity="low", asset=f"https://{name}",
                         evidence={"missing_header": "strict-transport-security"},
                         dedup_key=f"hdr:https://{name}:strict-transport-security",
                         status="ZU BESTÄTIGEN", source_colony="offensive")
    calls = []
    real = webapp.svc.remediate_and_recheck

    def spy(*a, **kw):
        calls.append((a, kw))
        return real(*a, **kw)

    monkeypatch.setattr(webapp.svc, "remediate_and_recheck", spy)
    url = f"/api/blue/findings/{fid}/remediate-recheck"

    assert client.post("/api/governance/kill", json={"confirm": "STOP"}).status_code == 200
    for body in ({"oversight_ack": True, "trigger_red_verify": True},
                 {"oversight_ack": True, "apply_fix": True},
                 {}):
        r = client.post(url, json=body)
        assert r.status_code == 423 and r.json()["kill_switch"] is True
    r = client.post(url + "/", json={"oversight_ack": True})
    assert r.status_code == 423
    assert calls == []                                   # kein Lauf, kein Service-Aufruf
    assert st.get_finding(fid)["status"] == "ZU BESTÄTIGEN"
    blocked = [e for e in client.get("/api/governance/audit?limit=10").json()["entries"]
               if e["action"] == "Fix + Re-Check"]
    assert blocked and all(e["result"] == "blocked" for e in blocked)

    assert client.post("/api/governance/reset", json={"confirm": "RESET"}).status_code == 200
    # Nach Reset: Startprüfung passiert, übliche Gates greifen weiter
    # (oversight_ack=False -> Red-Re-Check durch enforce_active_oversight blockiert).
    r = client.post(url, json={"oversight_ack": False, "trigger_red_verify": True})
    assert r.status_code == 200, r.text
    out = r.json()
    assert len(calls) == 1
    assert out["red_verify"]["ok"] is False and "BLOCKIERT" in out["red_verify"]["error"]
    assert out["outcome"] == "STILL_OPEN"
    entries = client.get("/api/governance/audit?limit=5").json()["entries"]
    assert entries[0]["action"] == "Fix + Re-Check" and entries[0]["result"] == "started"


def test_run_start_covers_remediate_recheck():
    from antbb.web import governance_routes as gr
    for path in ("/api/blue/findings/7/remediate-recheck",
                 "/api/blue/findings/7/remediate-recheck/"):
        hit = gr._match_run(path)
        assert hit is not None and hit[1] == "blue-remediation"
    assert gr._match_run("/api/blue/findings/x/remediate-recheck") is None
