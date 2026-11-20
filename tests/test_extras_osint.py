"""Extras (passiver OSINT-Katalog aus enna-Daten): Katalog, Filter, Gates,
Orchestrierung ueber die Rote Koenigin. Kein Netz: Runner werden gemockt."""
import json
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("ANTBB_NO_LLM", "1")

import pytest

from antbb import extras_osint as ex

FORBIDDEN = {"hidden-eye", "device-activity-tracker", "osintgram", "ghunt", "h8mail",
             "subjack", "goblin", "puredns", "shuffledns", "dnsenum", "holehe"}


def test_catalog_filtered_and_labelled():
    cat = ex.catalog()
    assert cat["label"] == "Extras"
    assert cat["count"] >= 30
    slugs = {t["slug"] for t in cat["tools"]}
    assert not (slugs & FORBIDDEN)
    for bad in ("phishing", "wireless", "exploitation", "offensive-ops", "password-attack"):
        assert bad in cat["excluded_categories"]
    assert all(t["id"].startswith("extras-") for t in cat["tools"])
    assert all(t["auto_install"] is False for t in cat["tools"])
    for t in cat["tools"]:
        h = t["install_hint"]
        assert "|" not in h and "curl" not in h and "&&" not in h
    assert "enna" not in json.dumps([t["name"] for t in cat["tools"]]).lower()


def test_runners_are_passive_only():
    for slug, spec in ex.RUNNERS.items():
        argv = " ".join(spec["argv"]("BIN", "example.org"))
        for flag in ("-active", "-brute", "--dns-brute", "-c ", "--screenshot", "-r "):
            assert flag not in argv + " ", (slug, flag)


@pytest.mark.parametrize("raw,want", [
    ("example.org", "example.org"), ("https://Example.org/x?y", "example.org"),
    ("*.example.org", "example.org"), ("-oX", ""), ("1.2.3.4", ""),
    ("a;rm -rf /", ""), ("", ""),
])
def test_clean_domain(raw, want):
    assert ex.clean_domain(raw) == want


def test_run_passive_missing_binary_is_honest(tmp_path, monkeypatch):
    monkeypatch.setattr(ex.shutil, "which", lambda b: None)
    res = ex.run_passive(["example.org", "-evil", "10.0.0.1"], ["subfinder"], tmp_path)
    assert res["passive_only"] and res["targets"] == ["example.org"]
    assert "nicht installiert" in res["results"][0]["note"]
    assert (tmp_path / "extras-osint.json").exists()


def _fake_subprocess(monkeypatch, calls):
    class P:
        returncode = 0
        stdout = "a.example.org\nb.example.org\n"
        stderr = ""

    def fake_run(argv, **kw):
        calls.append(argv)
        assert kw.get("timeout")
        assert "shell" not in kw
        return P()
    monkeypatch.setattr(ex.shutil, "which", lambda b: "/bin/" + b)
    monkeypatch.setattr(ex.subprocess, "run", fake_run)


@pytest.fixture
def hub(tmp_path, monkeypatch):
    from api.store import Settings, Store
    (tmp_path / "runs").mkdir()
    return Store(Settings(db_path=tmp_path / "colony.sqlite", data_dir=tmp_path / "runs"))


def test_queen_catalog_has_extras_soldier():
    from api.catalog import PLAYBOOKS, soldier_map
    ids = {p["playbook_id"] for p in PLAYBOOKS["red"]}
    assert "extras-osint" in ids and "extras-subfinder" in ids
    sol = soldier_map("red")["extras"]
    assert sol["name"] == "Extras" and "extras-osint" in sol["playbook_ids"]
    assert all(not p["destructive"] for p in PLAYBOOKS["red"] if p["playbook_id"].startswith("extras-"))


def test_queen_run_gates_and_real_execution(hub, monkeypatch):
    from api.store import ColonyError
    calls = []
    _fake_subprocess(monkeypatch, calls)
    # ohne Oversight-Haekchen
    with pytest.raises(ColonyError) as e:
        hub.start_run("red", "extras", "extras-osint", False, ["example.org"], None)
    assert e.value.status == 403
    # Haekchen, aber Kolonie-Oversight nicht scharf
    with pytest.raises(ColonyError) as e:
        hub.start_run("red", "extras", "extras-osint", True, ["example.org"], None)
    assert e.value.status == 403
    hub.set_oversight("red", True)
    # Scope leer -> default-deny
    with pytest.raises(ColonyError) as e:
        hub.start_run("red", "extras", "extras-osint", True, ["example.org"], None)
    assert e.value.status == 403
    hub.set_scope("red", ["example.org"])
    # ausserhalb der Allowlist
    with pytest.raises(ColonyError) as e:
        hub.start_run("red", "extras", "extras-osint", True, ["other.org"], None)
    assert e.value.status == 403
    assert calls == []
    dossier = hub.start_run("red", "extras", "extras-subfinder", True, ["example.org"], None)
    ev = dossier["evidence"]
    assert ev["executor"] == "extras-osint" and ev["passive_only"] is True
    assert dossier["stub"] is False
    assert ev["results"][0]["result_count"] == 2
    assert calls and calls[0][0] == "/bin/subfinder" and "example.org" in calls[0]


def test_colony_osint_agent_has_extras_playbook():
    from antbb.agents.osint import OsintHunterAnt
    assert "extras-osint" in [p.name for p in OsintHunterAnt.playbooks]


def test_colony_agent_runs_extras_only_on_request_and_in_scope(monkeypatch):
    import asyncio
    from antbb.agents.base import AgentContext, Task
    from antbb.agents.osint import OsintHunterAnt
    calls = []
    _fake_subprocess(monkeypatch, calls)
    import logging
    ctx = AgentContext(run_id="t", scope_check=lambda a: a == "example.org",
                       logger=logging.getLogger("t"))
    ant = OsintHunterAnt(ctx)
    t0 = Task(phase="scan", target_id=1, target_name="t", assets=["example.org"], params={})
    assert asyncio.run(ant._extras(t0)) == []
    t1 = Task(phase="scan", target_id=1, target_name="t", assets=["example.org", "evil.org"],
              params={"extras": True, "extras_tools": ["subfinder"]})
    found = asyncio.run(ant._extras(t1))
    assert found and all(f.category == "extras-osint" and f.severity == "info" for f in found)
    assert all("evil.org" not in c for c in calls)


# ---- Web: /osint zeigt "Extras", Lauf nur mit Gates -------------------------
ADMIN_PW = "Extras-OSINT-Admin!1"


@pytest.fixture
def web(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    from antbb import totp, webauth
    from antbb.store import Store
    monkeypatch.setenv("ANTBB_AUTH", "1")
    monkeypatch.setenv("ANTBB_ADMIN_USER", "mark")
    monkeypatch.setenv("ANTBB_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("ANTBB_DATA", str(tmp_path))
    monkeypatch.delenv("ANTBB_HOSTED", raising=False)
    monkeypatch.setenv("ANTBB_TOTP_KEY", "")
    totp.reset_cache()
    webauth.reset_login_throttle()
    from antbb.web.app import app, svc
    prev = svc.store
    svc.store = Store(str(tmp_path / "x.db"))
    webauth.bootstrap_admin(svc.store)
    yield app, svc
    svc.store.close()
    svc.store = prev
    totp.reset_cache()
    webauth.reset_login_throttle()


def _client(app, login=True):
    from fastapi.testclient import TestClient
    c = TestClient(app, headers={"origin": "http://testserver"})
    c.follow_redirects = False
    if login:
        assert c.post("/login", data={"username": "mark", "password": ADMIN_PW,
                                      "next": "/"}).status_code == 303
    return c


def test_osint_page_shows_extras(web):
    app, _ = web
    c = _client(app)
    html = c.get("/osint").text
    assert "Extras" in html and 'id="extras"' in html and "subfinder" in html
    assert "enna" not in html.lower().replace("quelle: enna", "")
    data = c.get("/api/osint/extras").json()
    assert data["label"] == "Extras" and data["count"] >= 30


def test_osint_extras_requires_login_and_gates(web, monkeypatch):
    app, svc = web
    anon = _client(app, login=False)
    assert anon.get("/api/osint/extras").status_code in (302, 303, 401, 403)
    assert anon.post("/osint/run", data={"target_id": 1, "extras": "1"}).status_code in (302, 303, 401, 403)
    calls = []
    _fake_subprocess(monkeypatch, calls)
    c = _client(app)
    tid = svc.add_target("t-extras") if hasattr(svc, "add_target") else None
    if tid is None:
        pytest.skip("kein add_target")
    tid = tid if isinstance(tid, int) else getattr(tid, "id", tid)
    r = c.post("/osint/run", data={"target_id": tid, "extras": "1"})
    assert r.status_code == 303
    assert "Oversight" in r.headers["location"] or "oversight" in r.headers["location"].lower() \
        or "Scope" in r.headers["location"]
    assert calls == []
