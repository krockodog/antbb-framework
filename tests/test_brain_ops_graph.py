"""ABPM-17: brain_ops.nodes_graph – Blue-Knoten, Brücken-Kanten, Yellow read-only.

Nur synthetische Fixtures (Ziele *.invalid, erfundene Hashes ohne Bezug zu
echten Proben), keine echten Scan-Daten. Die Datensätze werden über die
echten Store-APIs angelegt und tragen genau die Felder, die
bridge.remediate_and_recheck / queen / blue_queen / RecheckAnt real schreiben
(source_finding_id, parent_finding_id, run_group_id, dedup_key,
evidence.bridge_outcome/recheck/red_verify, Meta-Fund recheck-result).
yellow.db wird mit dem ECHTEN Schema aus yellow-queen/db.py angelegt.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest

from antbb import brain_ops
from antbb.store import Store

ROOT = Path(__file__).resolve().parents[1]
SHA = hashlib.sha256(b"abpm17-synthetic-sample").hexdigest()


def _yellow_schema() -> str:
    """SCHEMA-String aus yellow-queen/db.py (kein Duplikat, kein Import der
    Yellow-Pakete mit Seiteneffekten wie ensure_dirs)."""
    tree = ast.parse((ROOT / "yellow-queen" / "db.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == "SCHEMA" for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("SCHEMA in yellow-queen/db.py nicht gefunden")


def _make_yellow(tmp_path: Path, *, orch: object = None, orch_raw: str | None = None,
                 case_id: str = "yq-20260101-000000-abcdef12") -> tuple[Path, Path]:
    db = tmp_path / "ydata" / "yellow.db"
    db.parent.mkdir(parents=True)
    cases = tmp_path / "cases"
    cdir = cases / case_id
    (cdir / "evidence").mkdir(parents=True)
    c = sqlite3.connect(db)
    c.executescript(_yellow_schema())
    c.execute("INSERT INTO cases (id, queen_id, filename, sha256, size, kind, route, "
              "packed, status, dynamic, authorized, oversight, case_path, created_at, "
              "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
              (case_id, "yellow", "probe.exe", SHA, 64, "pe", "static", 1, "done",
               "none", 1, 1, str(cdir), "2026-01-01T00:00:00+01:00",
               "2026-01-01T00:00:00+01:00"))
    for idx, (op, skill, summ) in enumerate([
            ("triage", "triage", "Triage: PE, Packer-Hinweis UPX"),
            ("unpack", "upx", "UPX entpackt"),
            ("static", "analyzeHeadless", "Ghidra headless " + "x" * 500)]):
        c.execute("INSERT INTO hops (queen_id, case_id, idx, op, skill, status, "
                  "summary_de, warum, fund, next, ts) VALUES "
                  "('yellow',?,?,?,?,?,?,?,?,?,?)",
                  (case_id, idx, op, skill, "ok", summ, "", "", "[]",
                   "2026-01-01T00:00:00+01:00"))
    c.commit()
    c.close()
    if orch_raw is not None:
        (cdir / "orchestrator.json").write_text(orch_raw, encoding="utf-8")
    elif orch is not None:
        (cdir / "orchestrator.json").write_text(json.dumps(orch), encoding="utf-8")
    return db, cases


ORCH_OK = {
    "steps": {"triage": {"at": "2026-01-01T00:00:00Z", "ok": True,
                         "result": {"ok": True, "artifacts": ["triage_report.json"]}},
              "diec": {"at": "2026-01-01T00:00:01Z", "ok": False,
                       "result": {"ok": False, "error": "diec fehlt"}},
              "ghidra-mcp": {"at": "2026-01-01T00:00:02Z", "ok": True,
                             "result": {"ok": True, "decompiled": "A" * 50000}}},
    "findings": {"file": "sample.bin", "sha256": SHA, "is_pe": True,
                 "packer": ["UPX"], "ghidra_functions": 12, "strings_count": 40,
                 "sections": [{"name": ".upx0"}] * 30},
    "next_steps": [{"action": "frida", "label": "🪝 Frida-Hook (Lab)", "why": "..."}],
    "updated_at": "2026-01-01T00:00:03Z",
}


@pytest.fixture()
def world(tmp_path):
    """Red-Fund → Blue-Lauf/-Fund → Bridge-Re-Check, wie es die Pipeline schreibt."""
    st = Store(str(tmp_path / "antbb.db"))
    tid = st.add_target("brain-graph.invalid")
    st.add_scope(tid, "domain", "brain-graph.invalid")
    st.set_oversight(tid, True, confirmed_by="pytest")
    rg = "rg-abpm17test01"
    # Red-Lauf + Red-Fund (queen.py: source_colony=offensive)
    st.create_scan_run("run-red-1", tid, phases=["recon"], run_group_id=rg)
    red = st.add_finding(tid, "run-red-1", "headers", "Fehlender HSTS-Header",
                         "missing-header", "medium", asset="brain-graph.invalid",
                         evidence={"header": "strict-transport-security"},
                         dedup_key="missing-header:hsts:brain-graph.invalid",
                         status="VERIFIZIERT", run_group_id=rg,
                         source_colony="offensive")
    # Blue-Lauf mit parent_finding_id (blue_queen.py: run_id blue-…, meta.colony)
    st.create_scan_run("blue-abc123", tid, phases=["audit"],
                       meta={"colony": "blue"}, run_group_id=rg,
                       parent_finding_id=red)
    blue = st.add_finding(tid, "blue-abc123", "blue-webharden", "HSTS gesetzt",
                          "blue-webharden-fixed", "info", asset="brain-graph.invalid",
                          dedup_key="blue-webharden:hsts", status="BESTÄTIGT(PASSIV)",
                          run_group_id=rg, source_finding_id=red)
    # Re-Check-Lauf (queen.run_scan phases=recheck, parent_finding_id=red)
    st.create_scan_run("run-recheck-1", tid, phases=["recheck"], run_group_id=rg,
                       parent_finding_id=red)
    meta_f = st.add_finding(tid, "run-recheck-1", "recheck", "Re-Check (header): nicht mehr vorhanden",
                            "recheck-result", "info", asset="brain-graph.invalid",
                            evidence={"recheck_of": "missing-header:hsts:brain-graph.invalid",
                                      "recheck_kind": "header", "reproduced": False,
                                      "detail": {}},
                            dedup_key="recheck:run-recheck-1:missing-header:hsts",
                            status="REFERENZ", run_group_id=rg,
                            parent_finding_id=red, source_colony="offensive",
                            source_finding_id=red)
    # Bridge-Persistenz am Red-Fund (bridge.remediate_and_recheck)
    st.update_finding_bridge(red, status="MITIGATED", run_group_id=rg,
                             source_finding_id=red, extra_evidence={
                                 "recheck": {"finding_key": "missing-header:hsts",
                                             "title": "HSTS", "fix_action": "HSTS-Header setzen",
                                             "verify_method": "header-check", "closed": None,
                                             "evidence": {}},
                                 "red_verify": {"run_id": "run-recheck-1", "run_group_id": rg,
                                                "mode": "targeted", "parse_degraded": True,
                                                "reproduced": False, "recheck_kind": "header",
                                                "note": "Tool-Ausgaben teilweise unlesbar"},
                                 "run_group_id": rg, "bridge_outcome": "MITIGATED",
                                 "apply": {"applied": False,
                                           "reason": "offensive_finding_no_auto_apply"},
                             })
    # Lokaler Blue-Lauf ohne Target (nur run_history, mode=blue)
    st.add_run_history("blue-local01", None, target_name="localhost (lokales System)",
                       mode="blue", status="done", finding_count=0,
                       started_by="pytest", run_group_id="rg-local")
    # Blue-AV-Fund mit sha256 (agents/blue/av.py) → Korrelation zu Yellow
    av = st.add_finding(tid, "blue-abc123", "blue-av", "[QUARANTÄNE] /tmp/x",
                        "blue-av-infection", "high", asset="/srv/probe.exe",
                        evidence={"path": "/srv/probe.exe", "sha256": SHA},
                        dedup_key=f"blue-av-quarantine:{SHA}", status="ZU BESTÄTIGEN")
    yield {"store": st, "tid": tid, "red": red, "blue": blue, "meta": meta_f,
           "av": av, "rg": rg, "tmp": tmp_path}
    st._conn.close()


def _edges(g, kind):
    return {(e["from"], e["to"]) for e in g["edges"] if e["kind"] == kind}


def _node(g, nid):
    return next((n for n in g["nodes"] if n["id"] == nid), None)


def _no_yellow(tmp_path):
    return {"yellow_db_path": str(tmp_path / "nope" / "yellow.db"),
            "yellow_case_root": str(tmp_path / "nocases")}


# ---------------------------------------------------------------- Schritt 1
def test_blue_runs_and_findings_visible_by_default(world):
    g = brain_ops.nodes_graph(world["store"], **_no_yellow(world["tmp"]))
    assert g["counts"]["include_blue"] is True
    br = _node(g, "run:blue-abc123")
    assert br and br["type"] == "blue_run" and br["colony"] == "blue"
    assert br["target"] == "brain-graph.invalid" and br["run_id"] == "blue-abc123"
    assert br["run_group_id"] == world["rg"] and br["parent_finding_id"] == world["red"]
    local = _node(g, "run:blue-local01")
    assert local and local["type"] == "blue_run" and local["source"] == "run_history"
    assert local["target_id"] is None and local["target"] == "localhost (lokales System)"
    bf = _node(g, f"finding:{world['blue']}")
    assert bf["type"] == "blue_finding" and bf["colony"] == "blue"
    assert bf["status"] == "BESTÄTIGT(PASSIV)" and bf["run_id"] == "blue-abc123"
    rf = _node(g, f"finding:{world['red']}")
    assert rf["type"] == "finding" and rf["colony"] == "offensive"
    assert rf["bridge_outcome"] == "MITIGATED"
    assert g["counts"]["blue_runs"] == 2 and g["counts"]["blue_findings"] == 2


def test_include_blue_false_and_colonies_filter(world):
    g = brain_ops.nodes_graph(world["store"], include_blue=False, include_yellow=False)
    types = {n["type"] for n in g["nodes"]}
    assert not types & {"blue_run", "blue_finding", "blue_action"}
    assert not any(n["id"].startswith("soldier:blue") for n in g["nodes"])
    g2 = brain_ops.nodes_graph(world["store"], colonies=("blue",))
    t2 = {n["type"] for n in g2["nodes"]}
    assert "blue_run" in t2 and "finding" not in t2 and "run" not in t2
    assert g2["counts"]["colonies"] == ["blue"]


def test_setting_none_respects_brain_include_blue(world):
    world["store"].set_setting("brain.include_blue", "0")
    g = brain_ops.nodes_graph(world["store"], include_blue=None, include_yellow=False)
    assert g["counts"]["include_blue"] is False


def test_broken_metadata_warns_instead_of_abort(world):
    st = world["store"]
    st._conn.execute("UPDATE scan_runs SET meta='{kaputt' WHERE run_id='blue-abc123'")
    st._conn.execute("UPDATE findings SET evidence='nicht-json' WHERE id=?", (world["blue"],))
    st._conn.commit()
    g = brain_ops.nodes_graph(st, **_no_yellow(world["tmp"]))
    assert _node(g, "run:blue-abc123")["type"] == "blue_run"   # Fallback run_id blue-
    assert _node(g, f"finding:{world['blue']}") is not None
    assert g["counts"]["warnings"] >= 2
    assert any("scan_runs[blue-abc123].meta" in w for w in g["warnings"])


# ---------------------------------------------------------------- Schritt 2
def test_remediated_and_verified_edges(world):
    g = brain_ops.nodes_graph(world["store"], **_no_yellow(world["tmp"]))
    red, blue = f"finding:{world['red']}", f"finding:{world['blue']}"
    action = f"blue-action:{world['red']}"
    rem = _edges(g, "remediated_by")
    assert (red, blue) in rem                       # source_finding_id
    assert (red, "run:blue-abc123") in rem          # Blue-Lauf parent_finding_id
    assert (red, action) in rem                     # Bridge-Aktion
    act = _node(g, action)
    assert act["type"] == "blue_action" and act["status"] == "MITIGATED"
    assert act["bridge"]["parse_degraded"] is True
    assert act["bridge"]["apply_reason"] == "offensive_finding_no_auto_apply"
    ver = [e for e in g["edges"] if e["kind"] == "verified_by"]
    assert len(ver) == 1 and ver[0]["from"] == action and ver[0]["to"] == "run:run-recheck-1"
    assert ver[0]["outcome"] == "MITIGATED" and ver[0]["parse_degraded"] is True
    assert ver[0]["reproduced"] is False
    rch = _edges(g, "rechecked_by")
    assert (red, "run:run-recheck-1") in rch
    assert (red, f"finding:{world['meta']}") in rch     # RecheckAnt-Meta via recheck_of
    # keine Selbstschleife durch source_finding_id == eigene id
    assert not any(e["from"] == e["to"] for e in g["edges"])


def test_edges_deduplicated_and_deterministic(world):
    g1 = brain_ops.nodes_graph(world["store"], **_no_yellow(world["tmp"]))
    g2 = brain_ops.nodes_graph(world["store"], **_no_yellow(world["tmp"]))
    keys = [(e["from"], e["to"], e["kind"]) for e in g1["edges"]]
    assert len(keys) == len(set(keys))
    assert keys == [(e["from"], e["to"], e["kind"]) for e in g2["edges"]]
    ids = [n["id"] for n in g1["nodes"]]
    assert len(ids) == len(set(ids))


def test_edge_set_dedup_and_path_guard():
    es = brain_ops._EdgeSet()
    assert es.add("a", "b", "remediated_by") is True
    assert es.add("a", "b", "remediated_by") is False
    assert es.add("a", "b", "verified_by") is True
    assert es.add("a", "a", "remediated_by") is False
    assert es.add("a", "zz", "remediated_by", {"a", "b"}) is False
    assert es.skipped_missing == 1 and len(es.edges) == 2


# ---------------------------------------------------------------- Schritt 3
def test_yellow_readonly_import(world):
    db, cases = _make_yellow(world["tmp"], orch=ORCH_OK)
    before = (db.read_bytes(), db.stat().st_mtime_ns)
    g = brain_ops.nodes_graph(world["store"], yellow_db_path=str(db),
                              yellow_case_root=str(cases))
    after = (db.read_bytes(), db.stat().st_mtime_ns)
    assert before == after                                  # yellow.db unverändert
    yc = _node(g, "yellow-case:yq-20260101-000000-abcdef12")
    assert yc["type"] == "yellow_case" and yc["status"] == "done"
    assert yc["asset"] == "probe.exe" and yc["target"] is None and yc["sha256"] == SHA
    assert {"diec", "upx", "analyzeHeadless", "ghidra-mcp"} <= set(yc["tools"])
    assert len(yc["summary"]) <= 200
    assert yc["orchestrator"]["steps"] == {"triage": True, "diec": False, "ghidra-mcp": True}
    assert yc["orchestrator"]["findings"]["ghidra_functions"] == 12
    blob = json.dumps(yc)
    assert "AAAA" not in blob and ".upx0" not in blob       # keine Roh-Dumps
    assert g["counts"]["yellow_cases"] == 1 and g["counts"]["yellow_status"] == "ok"
    assert (f"finding:{world['av']}", yc["id"]) in _edges(g, "analyzed_by_yellow")
    assert not any(n["type"] == "yellow_hop" for n in g["nodes"])


def test_yellow_missing_db_no_crash(world, tmp_path):
    missing = tmp_path / "gibtsnicht" / "yellow.db"
    g = brain_ops.nodes_graph(world["store"], yellow_db_path=str(missing),
                              yellow_case_root=str(tmp_path))
    assert g["counts"]["yellow_status"] == "missing" and g["counts"]["yellow_cases"] == 0
    assert not missing.exists() and not missing.parent.exists()   # nie angelegt


@pytest.mark.parametrize("raw", ["{kaputt", "[1, 2, 3]"])
def test_yellow_broken_orchestrator_json(world, raw):
    db, cases = _make_yellow(world["tmp"], orch_raw=raw)
    res = brain_ops._load_yellow_brain_nodes(str(db), str(cases))
    assert res["status"] == "ok" and len(res["nodes"]) == 1
    assert "orchestrator.json" in res["nodes"][0]["warn"]
    assert any("orchestrator.json" in w for w in res["warnings"])


def test_yellow_case_dir_via_case_root_when_case_path_empty(world):
    db, cases = _make_yellow(world["tmp"], orch=ORCH_OK)
    c = sqlite3.connect(db)
    c.execute("UPDATE cases SET case_path=''")
    c.commit()
    c.close()
    res = brain_ops._load_yellow_brain_nodes(str(db), str(cases))
    assert res["nodes"][0]["orchestrator"]["steps"]["triage"] is True


def test_yellow_connection_is_really_readonly(world):
    db, _ = _make_yellow(world["tmp"])
    conn = brain_ops._open_yellow_ro(str(db))
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("INSERT INTO events (case_id, kind, message, ts) VALUES ('x','y','z','t')")
    conn.close()


def test_yellow_db_without_tables(world):
    db = world["tmp"] / "leer.db"
    sqlite3.connect(db).close()
    res = brain_ops._load_yellow_brain_nodes(str(db), str(world["tmp"]))
    assert res["status"] == "ok" and res["nodes"] == []
    assert any("cases" in w for w in res["warnings"])


def test_node_detail_new_types(world):
    d = brain_ops.node_detail(world["store"], "blue-action", str(world["red"]))
    assert d["ok"] and d["bridge"]["outcome"] == "MITIGATED"
    d2 = brain_ops.node_detail(world["store"], "blue-action", str(world["blue"]))
    assert d2 == {"ok": False, "reason": "no_bridge_action"}


# ---------------------------------------------------------------- Schritt 4
def test_graph_is_read_only_gates_untouched(world):
    """Graph-Aufbau ändert weder Scope/Oversight/Settings (inkl. Kill-Switch)
    noch Funde/Läufe – reiner Lesezugriff."""
    from antbb import governance
    st = world["store"]
    st.set_setting(governance.KILL_KEY, json.dumps({"active": False}))

    def snap():
        out = {}
        for tbl in ("scopes", "oversight", "settings", "findings", "scan_runs",
                    "run_history", "targets"):
            out[tbl] = [tuple(r) for r in st._conn.execute(f"SELECT * FROM {tbl} ORDER BY 1")]
        return out

    before = snap()
    ks_before = governance.kill_state(st)
    db, cases = _make_yellow(world["tmp"], orch=ORCH_OK)
    brain_ops.nodes_graph(st, yellow_db_path=str(db), yellow_case_root=str(cases))
    brain_ops.nodes_graph(st, colonies=("offensive",))
    assert snap() == before
    assert governance.kill_state(st) == ks_before
    assert st.is_confirmed(world["tid"]) is True


def test_brain_ops_has_no_gate_writes():
    """brain_ops importiert keine Scope-/Oversight-/Governance-Schreibpfade."""
    src = (ROOT / "antbb" / "brain_ops.py").read_text(encoding="utf-8")
    for forbidden in ("set_oversight", "add_scope", "enforce_active_oversight",
                      "from .governance", "import governance", "set_kill"):
        assert forbidden not in src, forbidden


def test_no_db_or_secret_artifacts_tracked():
    """Keine DB-/Env-/Daten-Artefakte im Git-Index (Gegenprobe ABPM-17)."""
    if not (ROOT / ".git").exists():
        pytest.skip("kein Git-Checkout")
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                             text=True, timeout=30, check=True).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git nicht verfügbar")
    bad = [p for p in out if p.endswith((".db", ".sqlite", ".sqlite3"))
           or os.path.basename(p) in (".env", "antbb.env")
           or p.startswith("data/")]
    assert bad == [], bad
