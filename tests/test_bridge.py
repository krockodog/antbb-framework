"""Tests für die Red→Blue→Re-Check-Brücke (ABPM-13 A + B + E).

A  Red-Fund → Fix-Zuordnung (remediation.red_recheck_spec / plan_fix /
   verify_closed) und enger Re-Check GENAU EINES Befunds (Phase "recheck").
B  Abgleich im Re-Check über den dedup_key statt nur über das Asset.
E  Brücken-Tests + keine stillen except-Blöcke in bridge.py.

Integrationsfälle laufen ECHT: Service → run_scan (alle Gates) → Queen →
RecheckAnt → scope-gebundener NetClient → lokaler HTTP-Testserver auf
127.0.0.1 (Inhalte vom Test festgelegt, keine echten Scan-Daten) → Store.
Ersetzt wird nur der externe LLM-Vorschlag, damit kein LLM/Netz außerhalb
des Testservers angefasst wird. Status-Semantik bleibt
MITIGATED / VERIFIED / STILL_OPEN (kein neuer Statuswert).
"""
from __future__ import annotations

import ast
import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from antbb import bridge, remediation
from antbb.agents import WORKER_AGENTS
from antbb.agents.base import AgentFinding
from antbb.agents.recheck import RECHECK_CATEGORY, RecheckAnt
from antbb.queen import PHASES
from antbb.service import AntBBService

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_OUTCOMES = {bridge.STATUS_MITIGATED, bridge.STATUS_VERIFIED, bridge.STATUS_STILL_OPEN}


# ===========================================================================
# Lokaler Testserver (echte HTTP-Antworten, vom Test gesteuert)
# ===========================================================================
class _Site:
    def __init__(self):
        self.headers: dict[str, str] = {}
        self.paths: dict[str, tuple[int, str]] = {}
        self.hits: list[str] = []


def _handler(site: _Site):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            site.hits.append(self.path)
            status, body = site.paths.get(self.path, (404, "not found"))
            if self.path == "/":
                status, body = 200, "<html><body>ok</body></html>"
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            for k, v in site.headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):  # Testausgabe ruhig halten
            return

    return H


@pytest.fixture
def site():
    s = _Site()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler(s))
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    s.base = f"http://127.0.0.1:{srv.server_address[1]}"
    yield s
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def svc(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTBB_NO_LLM", "1")
    monkeypatch.setenv("ANTBB_SCAN_MAX_RPS", "100")
    monkeypatch.delenv("ANTBB_HOSTED", raising=False)
    monkeypatch.setattr(remediation, "llm_suggest_remediation",
                        lambda finding, svc=None, max_retries=1:
                        {"ok": True, "llm_status": "not_called_in_test"})
    s = AntBBService(db_path=str(tmp_path / "bridge.db"))
    yield s
    s.close()


def _target(svc, *, oversight=True) -> int:
    tid = svc.store.add_target("bridge-test")
    svc.store.add_scope(tid, "ip", "127.0.0.1")
    svc.set_oversight(tid, oversight, confirmed_by="test")
    return tid


def _finding(svc, tid, **kw) -> int:
    base = dict(target_id=tid, run_id="run-red-1", agent="scanning",
                severity="medium", status="ZU BESTÄTIGEN", source_colony="offensive")
    base.update(kw)
    return svc.store.add_finding(**base)


# ===========================================================================
# A: Spezifikation + konkrete Fix-Hinweise
# ===========================================================================
SPEC_CASES = [
    ("misconfig", "http://h.test", {"missing_header": "strict-transport-security"},
     "hdr:http://h.test:strict-transport-security", remediation.RED_KIND_HEADER),
    ("tls", "h.test:443", {"protocol": "TLSv1"}, "tls-weak:h.test", remediation.RED_KIND_TLS),
    ("tls-scan", "h.test", {"weak_protocols": ["TLSv1.0"], "tool": "sslscan"},
     "tls-scan-weak:h.test", remediation.RED_KIND_TLS),
    ("info-disclosure", "http://h.test/.git/", {"path": "/.git/", "status": 200},
     "sensitive:http://h.test/.git/", remediation.RED_KIND_PATH),
    ("exposed-artifact", "http://h.test/.env", {"request": {"method": "GET"}},
     "exposed-artifact:http://h.test/.env", remediation.RED_KIND_PATH),
    ("content-discovery", "http://h.test/admin", {"path": "/admin", "status": 403, "tool": "gobuster"},
     "content-discovery:http://h.test/admin", remediation.RED_KIND_PATH),
    ("nikto-finding", "http://h.test/", {"tool": "nikto", "id": "999957"},
     "nikto:http://h.test/:999957", remediation.RED_KIND_NIKTO),
    ("version-disclosure", "http://h.test", {"tool": "wpscan", "version": "6.4.2",
                                             "package": "wordpress"},
     "wpscan-version:http://h.test", remediation.RED_KIND_VERSION),
    ("whatweb-fingerprint", "http://h.test", {"tool": "whatweb", "tech": {"nginx": "1.18.0", "HTML5": ""}},
     "whatweb:http://h.test", remediation.RED_KIND_VERSION),
    ("secret-exposure", "/srv/app", {"tool": "trufflehog", "detector": "AWS", "location": "/srv/app/x",
                                     "masked": "AKIA…******…XY",
                                     "command": "trufflehog filesystem /srv/app --json"},
     "secret:AWS:/srv/app/x:AKIA…******…XY", remediation.RED_KIND_SECRET),
    ("nuclei-finding", "http://h.test/.git/config", {"tool": "nuclei", "template_id": "git-config",
                                                     "matched_at": "http://h.test/.git/config"},
     "nuclei:git-config:http://h.test/.git/config", remediation.RED_KIND_NUCLEI),
]


@pytest.mark.parametrize("cat,asset,ev,dedup,kind", SPEC_CASES)
def test_red_spec_and_concrete_fix(cat, asset, ev, dedup, kind):
    f = {"category": cat, "asset": asset, "evidence": ev, "dedup_key": dedup,
         "title": f"t-{cat}", "status": "ZU BESTÄTIGEN"}
    spec = remediation.red_recheck_spec(f)
    assert spec is not None and spec["kind"] == kind
    assert spec["dedup_key"] == dedup and spec["asset"] == asset
    step = remediation.plan_fix(f)
    assert step.fix_action != "Konfiguration/Version gemäß Finding korrigieren."
    assert step.fix_command == ""          # kein Auto-Apply für Red-Funde
    assert step.evidence["recheck_spec"]["kind"] == kind
    closed = remediation.verify_closed(f)
    assert closed.closed is None and closed.evidence["recheck_kind"] == kind


def test_spec_details():
    f = {"category": "misconfig", "asset": "http://h.test", "dedup_key": "hdr:x",
         "evidence": {"missing_header": "Strict-Transport-Security"}}
    spec = remediation.red_recheck_spec(f)
    assert spec["header"] == "strict-transport-security" and spec["url"] == "http://h.test/"
    assert "max-age=31536000" in remediation.plan_fix(f).fix_action
    cd = remediation.red_recheck_spec({"category": "content-discovery", "asset": "http://h.test/a",
                                       "evidence": {"status": 403}})
    assert cd["orig_http_status"] == 403 and cd["path"] == "/a"
    sec = remediation.red_recheck_spec({"category": "secret-exposure", "asset": "repo",
                                        "evidence": {"tool": "trufflehog",
                                                     "command": "trufflehog git repo --json"}})
    assert sec["mode"] == "git"
    assert "Rotation" in remediation.plan_fix({"category": "secret-exposure", "asset": "repo",
                                               "evidence": {"tool": "trufflehog"}}).verify_method


@pytest.mark.parametrize("finding", [
    {"category": "misconfig", "asset": "http://h.test", "evidence": {}},          # Header fehlt
    {"category": "tls", "asset": "h.test:443", "dedup_key": "tls:h.test",
     "evidence": {"protocol": "TLSv1.3"}},                                         # kein Schwach-Fund
    {"category": "info-disclosure", "asset": "http://h.test/x", "evidence": {}},  # ohne path
    {"category": "whatweb-fingerprint", "asset": "http://h.test",
     "evidence": {"tech": {"HTML5": ""}}},                                         # keine Versionen
    {"category": "nuclei-finding", "asset": "http://h.test", "evidence": {}},     # ohne Template
    {"category": "sqli-verified", "asset": "http://h.test", "evidence": {}},      # nicht abgedeckt
    {"category": "blue-hardening-gap", "asset": "localhost", "evidence": {}},     # Blue
    {"category": "misconfig", "asset": "", "evidence": {"missing_header": "x"}},  # ohne Asset
])
def test_no_spec_without_required_fields(finding):
    assert remediation.red_recheck_spec(finding) is None


def test_uncovered_category_keeps_generic_plan():
    step = remediation.plan_fix({"category": "sqli-verified", "asset": "http://h.test"})
    assert step.fix_action == "Konfiguration/Version gemäß Finding korrigieren."


# ===========================================================================
# B: Abgleich über dedup_key
# ===========================================================================
def _af(cat, asset, key, status="ZU BESTÄTIGEN", **ev):
    return AgentFinding(agent="x", title=key, category=cat, severity="low", asset=asset,
                        evidence=ev, dedup_key=key, status=status)


def test_related_matches_dedup_key_only():
    finding = {"category": "misconfig", "asset": "http://h", "dedup_key": "hdr:http://h:hsts"}
    others_same_host = [_af("misconfig", "http://h", "hdr:http://h:csp"),
                        _af("info-disclosure", "http://h", "sensitive:http://h/.env")]
    assert bridge.related_open_findings(others_same_host, finding) == []
    same = _af("misconfig", "http://h", "hdr:http://h:hsts")
    assert bridge.related_open_findings(others_same_host + [same], finding) == [same]


def test_related_ignores_meta_and_closed_status():
    finding = {"category": "misconfig", "asset": "http://h", "dedup_key": "k"}
    meta = _af(RECHECK_CATEGORY, "http://h", "k")
    ref = _af("misconfig", "http://h", "k", status="REFERENZ")
    assert bridge.related_open_findings([meta, ref], finding) == []


def test_related_falls_back_to_category_and_asset_without_dedup():
    finding = {"category": "misconfig", "asset": "http://h", "dedup_key": ""}
    hit = _af("misconfig", "http://h", "irgendwas")
    other = _af("misconfig", "http://other", "x")
    assert bridge.related_open_findings([hit, other], finding) == [hit]


# ===========================================================================
# Integration: enger Re-Check über Service/Gates/Queen/RecheckAnt
# ===========================================================================
def test_header_still_missing_stays_open(svc, site):
    tid = _target(svc)
    fid = _finding(svc, tid, title="Fehlender Security-Header: strict-transport-security",
                   category="misconfig", asset=site.base,
                   evidence={"missing_header": "strict-transport-security"},
                   dedup_key=f"hdr:{site.base}:strict-transport-security")
    out = svc.remediate_and_recheck(fid, oversight_ack=True, trigger_red_verify=True)
    rv = out["red_verify"]
    assert out["outcome"] == bridge.STATUS_STILL_OPEN
    assert rv["mode"] == "targeted" and rv["match"] == "dedup_key"
    assert rv["reproduced"] is True and rv["related_open"] == 1
    assert rv["recheck_detail"]["reason"] == "header_missing"
    assert site.hits == ["/"]                                # genau ein Request, nur dieser Befund


def test_header_fixed_is_mitigated_despite_other_open_issue_on_host(svc, site):
    site.headers = {"Strict-Transport-Security": "max-age=31536000"}   # CSP fehlt weiterhin
    tid = _target(svc)
    _finding(svc, tid, title="Fehlender Security-Header: content-security-policy",
             category="misconfig", asset=site.base,
             evidence={"missing_header": "content-security-policy"},
             dedup_key=f"hdr:{site.base}:content-security-policy")
    fid = _finding(svc, tid, title="Fehlender Security-Header: strict-transport-security",
                   category="misconfig", asset=site.base,
                   evidence={"missing_header": "strict-transport-security"},
                   dedup_key=f"hdr:{site.base}:strict-transport-security")
    out = svc.remediate_and_recheck(fid, oversight_ack=True, trigger_red_verify=True)
    assert out["outcome"] == bridge.STATUS_MITIGATED
    assert out["red_verify"]["reproduced"] is False
    row = svc.store.get_finding(fid)
    assert row["status"] == bridge.STATUS_MITIGATED
    ev = json.loads(row["evidence"])
    assert ev["bridge_outcome"] == bridge.STATUS_MITIGATED
    assert ev["red_verify"]["recheck_kind"] == remediation.RED_KIND_HEADER


@pytest.mark.parametrize("served,expected,reason", [
    ((200, "APP_ENV=test\nDEBUG=false\n"), bridge.STATUS_STILL_OPEN, "artifact_content_present"),
    ((404, "not found"), bridge.STATUS_MITIGATED, "gone"),
    ((200, "<html>Willkommen</html>"), bridge.STATUS_MITIGATED, "artifact_content_gone"),
])
def test_exposed_artifact_recheck(svc, site, served, expected, reason):
    site.paths["/.env"] = served
    tid = _target(svc)
    url = site.base + "/.env"
    fid = _finding(svc, tid, title="Exponiertes Artefakt bestätigt: /.env",
                   category="exposed-artifact", severity="high", asset=url,
                   evidence={"request": {"method": "GET", "url": url}},
                   dedup_key=f"exposed-artifact:{url}")
    out = svc.remediate_and_recheck(fid, oversight_ack=True, trigger_red_verify=True)
    assert out["outcome"] == expected
    assert out["red_verify"]["recheck_detail"]["reason"] == reason
    assert site.hits == ["/.env"]


def test_oversight_denied_runs_nothing(svc, site):
    tid = _target(svc)
    fid = _finding(svc, tid, title="hsts", category="misconfig", asset=site.base,
                   evidence={"missing_header": "strict-transport-security"},
                   dedup_key=f"hdr:{site.base}:strict-transport-security")
    out = svc.remediate_and_recheck(fid, oversight_ack=False, trigger_red_verify=True)
    assert out["outcome"] == bridge.STATUS_STILL_OPEN
    assert out["red_verify"]["ok"] is False and "BLOCKIERT" in out["red_verify"]["error"]
    assert site.hits == []


def test_target_without_oversight_skips_recheck(svc, site):
    tid = _target(svc, oversight=False)
    fid = _finding(svc, tid, title="hsts", category="misconfig", asset=site.base,
                   evidence={"missing_header": "strict-transport-security"},
                   dedup_key=f"hdr:{site.base}:strict-transport-security")
    out = svc.remediate_and_recheck(fid, oversight_ack=True, trigger_red_verify=True)
    assert out["outcome"] == bridge.STATUS_STILL_OPEN
    # Target-Oversight fehlt -> run_scan-Gate blockiert hart, kein Request
    assert out["red_verify"]["ok"] is False
    assert "OversightError" in out["red_verify"]["error"]
    assert site.hits == []


def test_out_of_scope_asset_is_not_requested(svc, site):
    tid = _target(svc)
    port = site.base.rsplit(":", 1)[1]
    other = f"http://localhost:{port}"                      # nicht in der Allowlist (nur 127.0.0.1)
    fid = _finding(svc, tid, title="hsts", category="misconfig", asset=other,
                   evidence={"missing_header": "strict-transport-security"},
                   dedup_key=f"hdr:{other}:strict-transport-security")
    out = svc.remediate_and_recheck(fid, oversight_ack=True, trigger_red_verify=True)
    assert out["outcome"] != bridge.STATUS_MITIGATED
    assert out["red_verify"]["reproduced"] is None
    assert out["red_verify"]["recheck_detail"]["reason"] == "out_of_scope"
    assert site.hits == []


@pytest.mark.skipif(shutil.which("nuclei") is not None, reason="nuclei installiert – Fall 'Tool fehlt'")
def test_missing_tool_is_not_proof_of_fix(svc, site):
    tid = _target(svc)
    url = site.base + "/.git/config"
    fid = _finding(svc, tid, title="nuclei: Git Config", category="nuclei-finding", asset=url,
                   evidence={"tool": "nuclei", "template_id": "git-config", "matched_at": url},
                   dedup_key=f"nuclei:git-config:{url}", status="VERIFIZIERT")
    out = svc.remediate_and_recheck(fid, oversight_ack=True, trigger_red_verify=True)
    assert out["red_verify"]["reproduced"] is None
    assert out["red_verify"]["recheck_detail"]["reason"] == "tool_missing"
    # Unveränderte Semantik: kein Gegenbeweis + ursprünglich VERIFIZIERT -> VERIFIED
    assert out["outcome"] == bridge.STATUS_VERIFIED
    assert svc.store.get_finding(fid)["status"] == "VERIFIZIERT"


def test_meta_result_is_persisted_but_not_in_blue_list(svc, site):
    tid = _target(svc)
    fid = _finding(svc, tid, title="hsts", category="misconfig", asset=site.base,
                   evidence={"missing_header": "strict-transport-security"},
                   dedup_key=f"hdr:{site.base}:strict-transport-security")
    svc.remediate_and_recheck(fid, oversight_ack=True, trigger_red_verify=True)
    metas = [r for r in svc.store.list_findings(tid) if r["category"] == RECHECK_CATEGORY]
    assert len(metas) == 1 and json.loads(metas[0]["evidence"])["reproduced"] is True
    listed = bridge.list_blue_visible_findings(svc.store, source_colony="offensive")
    assert all(r["category"] != RECHECK_CATEGORY for r in listed)


# ===========================================================================
# E: Fehlerbehandlung statt stiller except-Blöcke
# ===========================================================================
def test_corrupt_scan_run_meta_is_reported(svc, caplog):
    tid = svc.store.add_target("bridge-meta")
    svc.store.create_scan_run("run-corrupt", tid, phases=["scan"], meta={"x": 1})
    svc.store._conn.execute("UPDATE scan_runs SET meta=? WHERE run_id=?", ("{kaputt", "run-corrupt"))
    svc.store._conn.commit()
    fid = _finding(svc, tid, run_id="run-corrupt", title="t", category="sqli-verified",
                   asset="http://h.test", evidence={}, dedup_key="sqli:t")
    with caplog.at_level("WARNING", logger="antbb.bridge"):
        out = svc.remediate_and_recheck(fid, trigger_red_verify=False)
    assert out["ok"] is True and out["run_group_id"].startswith("rg-")
    assert len(out["warnings"]) == 1 and "scan_runs.meta" in out["warnings"][0]
    assert any("scan_runs.meta" in r.getMessage() for r in caplog.records)


def test_bridge_has_no_silent_except():
    tree = ast.parse((ROOT / "antbb/bridge.py").read_text(encoding="utf-8"))
    silent = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)
              and all(isinstance(s, ast.Pass) for s in n.body)]
    assert silent == []


def test_status_semantics_and_isolation_unchanged():
    assert (bridge.STATUS_MITIGATED, bridge.STATUS_VERIFIED, bridge.STATUS_STILL_OPEN) == \
        ("MITIGATED", "VERIFIED", "STILL_OPEN")
    assert "recheck" not in PHASES                 # normale Scans unverändert
    assert RecheckAnt not in WORKER_AGENTS         # Registry unverändert


def test_no_recheck_outcomes_outside_semantics(svc):
    tid = svc.store.add_target("bridge-semantics")
    fid = _finding(svc, tid, title="t", category="misconfig", asset="http://h.test",
                   evidence={"missing_header": "x-frame-options"}, dedup_key="hdr:h:xfo")
    out = svc.remediate_and_recheck(fid, trigger_red_verify=False)
    assert out["outcome"] in ALLOWED_OUTCOMES
