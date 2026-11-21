"""ABPM-13: parse_status/parse_warning (ABPM-12) im Red→Blue→Re-Check-Fluss.

Geprüft wird die Verdrahtung, nicht die Gates:
  * KaliAdapter schreibt Parse-Fallbacks zusätzlich in ``ctx.parse_events``
    (Lauf-Kontext) – auch wenn daraus kein Fund entsteht.
  * bridge.list_blue_visible_findings zeigt parse_status/parse_warning eines
    Red-Funds direkt an (Blue sieht die unsichere Herkunft).
  * bridge.remediate_and_recheck gibt ``source_parse`` zurück und persistiert es
    nur, wenn es gesetzt ist.
  * Red-Verify: Parse-Lage eines Laufs wird zusammengefasst.

Echte Komponenten: Service + Store (Temp-DB), plan_fix, verify_closed,
update_finding_bridge. Ersetzt wird nur der externe LLM-Vorschlag
(``remediation.llm_suggest_remediation``), damit der Test kein LLM/Netz anfasst;
Scope- und Oversight-Gates werden nicht berührt (apply_fix=False,
trigger_red_verify=False).
"""
from __future__ import annotations

import asyncio
import json
import logging

import pytest

from antbb import bridge, remediation
from antbb.agents.base import AgentContext, AgentFinding
from antbb.queen import SwarmResult
from antbb.service import AntBBService
from antbb.tools.kali import KaliAdapter, ToolResult
from antbb.tools.parsers import PARSE_PARTIAL

PARTIAL_EVIDENCE = {
    "tool": "nuclei", "template_id": "exposed-git",
    "parse_status": PARSE_PARTIAL, "parse_method": "jsonl",
    "parse_context": "kali.nuclei",
    "parse_warning": "kali.nuclei: 1 kaputte JSON-Zeile(n) verworfen",
}
CLEAN_EVIDENCE = {"tool": "nuclei", "template_id": "tech-detect"}


# ---------------------------------------------------------------------------
# kali → ctx.parse_events
# ---------------------------------------------------------------------------
def _ctx() -> AgentContext:
    return AgentContext(run_id="t-run", scope_check=lambda a: True,
                        logger=logging.getLogger("test.bridge_parse"))


def test_agent_context_has_empty_parse_events_by_default():
    assert _ctx().parse_events == []


def test_kali_parse_fallback_reaches_run_context(monkeypatch):
    ctx = _ctx()
    ad = KaliAdapter(ctx)

    async def _run(tool, argv, *, target, timeout=120.0, offensive=False, input_text=None):
        return ToolResult(tool=tool, available=True, ran=True, returncode=0,
                          stdout='{"template-id": "x", "info": {"na', command=[tool])

    monkeypatch.setattr(ad, "run", _run)
    out = asyncio.run(ad.nuclei("https://example.test/"))
    assert out == []                                   # kein Pseudo-Fund
    assert len(ctx.parse_events) == 1                  # aber im Lauf sichtbar
    assert ctx.parse_events[0]["parse_context"] == "kali.nuclei"
    assert ctx.parse_events == ad.parse_events


def test_swarm_result_has_parse_events_field():
    r = SwarmResult(run_id="r", target_id=1, target_name="t")
    assert r.parse_events == []


# ---------------------------------------------------------------------------
# bridge.parse_info / Red-Verify-Zusammenfassung
# ---------------------------------------------------------------------------
def test_parse_info_only_for_degraded_evidence():
    info = bridge.parse_info(PARTIAL_EVIDENCE)
    assert info == {"parse_status": PARSE_PARTIAL,
                    "parse_warning": PARTIAL_EVIDENCE["parse_warning"],
                    "parse_context": "kali.nuclei", "parse_method": "jsonl"}
    assert bridge.parse_info(CLEAN_EVIDENCE) is None
    assert bridge.parse_info(None) is None
    assert bridge.parse_info("kein dict") is None


def test_red_verify_parse_summary():
    swarm = SwarmResult(run_id="r", target_id=1, target_name="t", findings=[
        AgentFinding(agent="scanning", title="a", category="nuclei-finding",
                     severity="medium", evidence=dict(PARTIAL_EVIDENCE)),
        AgentFinding(agent="scanning", title="b", category="nuclei-finding",
                     severity="info", evidence=dict(CLEAN_EVIDENCE)),
    ], parse_events=[{"parse_context": "kali.nikto", "parse_status": PARSE_PARTIAL,
                      "parse_warning": "kali.nikto: json_decode"}])
    s = bridge._red_verify_parse(swarm)
    assert s["parse_degraded"] is True
    assert s["parse_event_count"] == 1 and s["parse_degraded_findings"] == 1
    clean = bridge._red_verify_parse(SwarmResult(run_id="r", target_id=1, target_name="t"))
    assert clean == {"parse_degraded": False, "parse_event_count": 0,
                     "parse_events": [], "parse_degraded_findings": 0}


# ---------------------------------------------------------------------------
# Blue-Liste + remediate_and_recheck mit echtem Service/Store
# ---------------------------------------------------------------------------
@pytest.fixture
def svc(tmp_path, monkeypatch):
    s = AntBBService(db_path=str(tmp_path / "bridge.db"))
    monkeypatch.setattr(remediation, "llm_suggest_remediation",
                        lambda finding, svc=None, max_retries=1:
                        {"ok": True, "llm_status": "not_called_in_test"})
    yield s
    s.close()


def _red_finding(store, tid: int, title: str, evidence: dict) -> int:
    return store.add_finding(
        target_id=tid, run_id="run-red-1", agent="scanning", title=title,
        category="nuclei-finding", severity="medium", asset="example.test",
        evidence=evidence, dedup_key=f"nuclei:{title}", status="ZU BESTÄTIGEN",
        source_colony="offensive")


def test_blue_list_shows_parse_warning_of_red_finding(svc):
    tid = svc.store.add_target("bridge-parse-list")
    _red_finding(svc.store, tid, "degraded", dict(PARTIAL_EVIDENCE))
    _red_finding(svc.store, tid, "clean", dict(CLEAN_EVIDENCE))
    rows = {r["title"]: r for r in bridge.list_blue_visible_findings(
        svc.store, source_colony="offensive")}
    assert rows["degraded"]["parse_status"] == PARSE_PARTIAL
    assert rows["degraded"]["parse_warning"].startswith("kali.nuclei: ")
    assert "parse_status" not in rows["clean"] and "parse_warning" not in rows["clean"]


def test_remediate_recheck_carries_source_parse(svc):
    tid = svc.store.add_target("bridge-parse-recheck")
    fid_bad = _red_finding(svc.store, tid, "degraded", dict(PARTIAL_EVIDENCE))
    fid_ok = _red_finding(svc.store, tid, "clean", dict(CLEAN_EVIDENCE))

    out = svc.remediate_and_recheck(fid_bad, apply_fix=False, trigger_red_verify=False)
    assert out["ok"] is True
    assert out["source_parse"]["parse_status"] == PARSE_PARTIAL
    ev = json.loads(svc.store.get_finding(fid_bad)["evidence"])
    assert ev["source_parse"]["parse_warning"] == PARTIAL_EVIDENCE["parse_warning"]

    out_ok = svc.remediate_and_recheck(fid_ok, apply_fix=False, trigger_red_verify=False)
    assert out_ok["ok"] is True and out_ok["source_parse"] is None
    ev_ok = json.loads(svc.store.get_finding(fid_ok)["evidence"])
    assert "source_parse" not in ev_ok
