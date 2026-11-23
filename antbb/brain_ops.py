"""Neuronales Gehirn der Königin — Node-/Log-Lesezugriff + HUMAN-ONLY
Lösch-/Reset-Operationen.

Scope (Lesen): Red/offensive Kolonie (Pentest/Bugbounty/WLAN) UND Blue
Queen (colony=blue: blue_run / blue_finding / blue_action) — per Parameter
``include_blue`` bzw. ``colonies`` filterbar — plus Yellow-Cases read-only aus
yellow.db (Source of Truth bleibt yellow.db, hier wird nie geschrieben).
Blue Queen behält zusätzlich ihre eigene Ansicht unter /blue.

================================ WICHTIG =================================
Die LÖSCH- und RESET-Funktionen in diesem Modul sind AUSSCHLIESSLICH für
einen Menschen über die Neuronales-Gehirn-GUI gedacht ("human-only").

  * Jede Lösch-/Reset-Operation verlangt ein ausdrückliches menschliches
    Bestätigungs-Flag (``human_confirm is True``). Dieses Flag setzt NUR der
    interaktive Web-UI-Handler nach einem Confirm-Dialog der Nutzerin.
  * Weder Soldaten noch die Königin (queen.py) noch die Agenten-Fassade in
    service.py dürfen diese Funktionen erreichen — sie importieren dieses
    Modul nicht und haben auf Logs/Läufe/Funde/Ziele nur LESENDEN Zugriff.
  * Ein Aufruf ohne gesetztes Bestätigungs-Flag wird HART abgelehnt
    (HumanConfirmError) und zusätzlich in data/brain_audit.log protokolliert.
  * Vor jeder harten Löschung ODER jedem Reset wird automatisch eine
    Zeitstempel-Sicherung von data/antbb.db nach data/backups/ angelegt,
    damit ein versehentlicher Purge wiederherstellbar ist.
  * antbb.env / Secrets werden NIE angefasst oder gesichert.
=========================================================================
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shutil
import time
from typing import Callable, Optional

from .store import Store

# Wortlaut, den die GUI im Confirm-Dialog zeigt und bestätigt.
HUMAN_CONFIRM_PROMPT = (
    "Human-Only Löschen/Zurücksetzen: Ich bestätige als verantwortlicher Mensch "
    "diese endgültige Aktion im Neuronalen Gehirn. (Automatisches DB-Backup wird "
    "angelegt. Agenten/Königin dürfen dies NICHT auslösen.)"
)


class HumanConfirmError(PermissionError):
    """Wird geworfen, wenn eine Lösch-/Reset-Operation ohne ausdrückliches
    menschliches Bestätigungs-Flag versucht wird (default-deny)."""



def _is_blue_agent(name: Optional[str]) -> bool:
    """Blue-Queen-Soldaten (colony=blue) – im Brain nur mit include_blue."""
    n = (name or "").strip().lower()
    return n.startswith("blue-") or n.startswith("blue_")


def _is_blue_run_id(run_id: Optional[str]) -> bool:
    """Blue-Queen-Läufe (run_id blue-…) – /blue und (include_blue) /brain."""
    r = (run_id or "").strip().lower()
    return r.startswith("blue-") or r.startswith("blue_")


def _audit_path(store: Store) -> str:
    return os.path.join(os.path.dirname(store.db_path), "brain_audit.log")


def _audit(store: Store, line: str) -> None:
    """Hängt eine Audit-Zeile an (NIE Secrets). Best-effort."""
    try:
        ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(_audit_path(store), "a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] {line}\n")
    except Exception:
        pass


def _require_human(store: Store, human_confirm, action: str) -> None:
    """HARTES, serverseitiges Default-Deny-Gate: human_confirm MUSS True sein.

    Dieser Guard lehnt JEDE Lösch-/Reset-Anfrage ohne menschliches
    Bestätigungs-Flag ab und protokolliert die Ablehnung. Er ist die einzige
    Pforte zu allen destruktiven Primitiven unten."""
    if human_confirm is not True:
        _audit(store, f"REJECT (kein Human-Confirm) · aktion={action} · "
                      f"flag={human_confirm!r}")
        raise HumanConfirmError(
            "BLOCKIERT (human-only): Diese Lösch-/Reset-Aktion darf NUR ein "
            "Mensch aus der Neuronales-Gehirn-GUI mit Bestätigung auslösen. "
            "Agenten und die Königin haben nur Lesezugriff.\n"
            f'  Bitte bestätigen: "{HUMAN_CONFIRM_PROMPT}"')


def backup_db(store: Store) -> str:
    """Zeitstempel-Sicherung von antbb.db nach data/backups/. Gibt den Pfad
    zurück. antbb.env / Secrets werden NIE kopiert."""
    db = store.db_path
    bdir = os.path.join(os.path.dirname(db), "backups")
    os.makedirs(bdir, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(bdir, f"{os.path.basename(db)}.bak-{stamp}")
    # Konsistente Online-Sicherung über die SQLite-Backup-API (offene Conn).
    try:
        import sqlite3
        with sqlite3.connect(dest) as bck:
            store._conn.backup(bck)  # type: ignore[attr-defined]
    except Exception:
        # Fallback: Dateikopie (DB ist klein, WAL hier nicht aktiv).
        shutil.copy2(db, dest)
    return dest


def _fmt(ts: Optional[float]) -> str:
    """Epoch -> lesbarer Zeitstempel in Box-lokaler Zeit (Europe/Berlin)."""
    if not ts:
        return ""
    try:
        return _dt.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


# ===================================================================
# LESEN (für alle erlaubt — Agenten/Queen/UI): Nodes, Node-Detail, Logs
# ===================================================================
_RUNNING = ("running", "paused", "queued", "stuck")


def _run_node_status(status: str) -> str:
    if status in ("running", "queued"):
        return "läuft"
    if status in ("paused", "stuck"):
        return "hängt"
    if status == "reset":
        return "zurückgesetzt"
    return status or "unbekannt"


# ===================================================================
# Graph-Bausteine (ABPM-17): Blue-Knoten, Brücken-Kanten, Yellow read-only
# ===================================================================
#: Kolonien, die der Brain-Graph standardmäßig zeigt (Red=offensive + Blue).
DEFAULT_COLONIES: tuple[str, ...] = ("offensive", "blue")
#: Obergrenzen, damit /api/brain/nodes handlich bleibt.
FINDING_CAP = 400
EXTRA_BLUE_RUN_CAP = 200
YELLOW_CASE_CAP = 50
WARN_CAP = 50
#: Kanten-Typen der Brücke Red → Blue → Re-Check / Yellow.
EDGE_REMEDIATED_BY = "remediated_by"
EDGE_VERIFIED_BY = "verified_by"
EDGE_RECHECKED_BY = "rechecked_by"
EDGE_ANALYZED_BY_YELLOW = "analyzed_by_yellow"
_RELATION_EDGES = frozenset({EDGE_REMEDIATED_BY, EDGE_VERIFIED_BY,
                             EDGE_RECHECKED_BY, EDGE_ANALYZED_BY_YELLOW})
#: Ausgänge von bridge.remediate_and_recheck (bridge.STATUS_*).
_BRIDGE_OUTCOMES = ("MITIGATED", "VERIFIED", "STILL_OPEN")
_RECHECK_CATEGORY = "recheck-result"   # antbb.agents.recheck.RECHECK_CATEGORY
#: orchestrator.json größer als das wird nicht gelesen (kein Roh-Dump im Brain).
ORCH_MAX_BYTES = 2 * 1024 * 1024
#: Yellow-Orchestrator-Schritte → RE-Werkzeug (yellow-queen/orchestrator.py).
_YELLOW_STEP_TOOLS = {"triage": "triage", "diec": "diec", "unpack": "upx",
                      "ghidra": "analyzeHeadless", "ghidra-mcp": "ghidra-mcp",
                      "frida": "frida"}
_YELLOW_CASE_ID_RE = re.compile(r"[^A-Za-z0-9_.-]")


class _Warn:
    """Sammelt Lese-/Parse-Warnungen statt den Graph-Aufbau abzubrechen."""

    def __init__(self) -> None:
        self.items: list[str] = []
        self.total = 0

    def add(self, msg: str) -> str:
        self.total += 1
        if len(self.items) < WARN_CAP:
            self.items.append(msg[:300])
        return msg[:300]


class _EdgeSet:
    """Deterministische Kanten-Dedup über (source_id, target_id, edge_type).

    Mehrfacher Graph-Aufbau oder doppelte Datenquellen erzeugen keine
    doppelten Kanten; Selbstschleifen werden verworfen. Beziehungs-Kanten
    (remediated_by/verified_by/rechecked_by/analyzed_by_yellow) werden nur
    gezogen, wenn beide Knoten im Graph liegen (Pfad-Schutz)."""

    def __init__(self) -> None:
        self.edges: list[dict] = []
        self._seen: set[tuple[str, str, str]] = set()
        self.skipped_missing = 0

    def add(self, src: str, dst: str, kind: str, node_ids: Optional[set] = None,
            **attrs) -> bool:
        if not src or not dst or src == dst:
            return False
        if node_ids is not None and (src not in node_ids or dst not in node_ids):
            self.skipped_missing += 1
            return False
        key = (src, dst, kind)
        if key in self._seen:
            return False
        self._seen.add(key)
        edge = {"from": src, "to": dst, "kind": kind}
        edge.update({k: v for k, v in attrs.items() if v is not None})
        self.edges.append(edge)
        return True


def _row_get(row, key: str, default=None):
    """.get() für sqlite3.Row UND dict – fehlende Spalte → default."""
    try:
        if isinstance(row, dict):
            return row.get(key, default)
        if key in row.keys():
            v = row[key]
            return default if v is None else v
    except (KeyError, IndexError, TypeError):
        pass
    return default


def _safe_json(raw, warn: _Warn, where: str, default=None):
    """JSON-Feld robust lesen; Fehler → Warnung + default (nie Abbruch)."""
    if default is None:
        default = {}
    if raw in (None, ""):
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as exc:
        warn.add(f"{where}: JSON nicht lesbar ({type(exc).__name__})")
        return default


def _as_int(v) -> Optional[int]:
    try:
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _finding_colony(f, evidence: dict) -> str:
    """Kolonie eines Funds aus echten Feldern (source_colony, agent, run_id,
    category blue-*) – dieselbe Logik wie bridge.finding_source_colony."""
    sc = str(_row_get(f, "source_colony", "") or "").strip().lower()
    if sc:
        return sc
    if _is_blue_agent(_row_get(f, "agent", "")) or _is_blue_run_id(_row_get(f, "run_id", "")):
        return "blue"
    if str(_row_get(f, "category", "") or "").startswith("blue-"):
        return "blue"
    return "offensive"


def _norm_colonies(colonies, include_blue: bool, include_yellow: bool) -> tuple[str, ...]:
    if colonies is None:
        out = ["offensive"]
        if include_blue:
            out.append("blue")
        if include_yellow:
            out.append("yellow")
        return tuple(out)
    if isinstance(colonies, str):
        colonies = colonies.split(",")
    out = []
    for c in colonies:
        c = str(c or "").strip().lower()
        if c in ("red", "offensiv"):
            c = "offensive"
        if c in ("offensive", "blue", "yellow") and c not in out:
            out.append(c)
    return tuple(out)


def _setting_bool(store: Store, key: str, default: str) -> bool:
    try:
        return store.get_setting(key, default).strip() in ("1", "true", "True", "yes")
    except Exception:
        return default in ("1", "true", "True", "yes")


# ------------------------- Yellow (read-only) -------------------------
def _yellow_case_roots(case_root=None) -> list[str]:
    """Case-Wurzeln: explizit > YQ_CASES_DIR > Yellow-Default (repo/cases,
    yellow-queen/config.CASES_DIR) > report_store-Default (yellow-queen/cases)."""
    if case_root:
        return [str(case_root)]
    roots: list[str] = []
    env = os.environ.get("YQ_CASES_DIR")
    if env:
        roots.append(env)
    else:
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        home = os.environ.get("YQ_HOME") or repo
        roots.append(os.path.join(home, "cases"))
        roots.append(os.path.join(repo, "yellow-queen", "cases"))
    return roots


def _open_yellow_ro(path: str):
    """yellow.db NUR lesend öffnen (sqlite URI mode=ro). Fehlt die Datei,
    wird NICHT angelegt (mode=ro legt nie an) → None."""
    import sqlite3
    import urllib.parse
    if not path or not os.path.isfile(path):
        return None
    uri = "file:" + urllib.parse.quote(os.path.abspath(path)) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _read_orchestrator_summary(case_dir: str, warn: _Warn, case_id: str) -> dict:
    """Kompakte Zusammenfassung aus <case>/orchestrator.json (echtes Schema aus
    yellow-queen/orchestrator.py: steps{action:{at,ok,result}}, findings{},
    next_steps[], updated_at). Keine Roh-Dumps, keine Binärdaten."""
    if not case_dir:
        return {}
    for p in (os.path.join(case_dir, "orchestrator.json"),
              os.path.join(case_dir, "state", "orchestrator.json")):
        if not os.path.isfile(p):
            continue
        try:
            size = os.path.getsize(p)
            if size > ORCH_MAX_BYTES:
                return {"warn": warn.add(f"yellow {case_id}: orchestrator.json zu groß "
                                         f"({size} B) – nicht gelesen")}
            with open(p, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            return {"warn": warn.add(f"yellow {case_id}: orchestrator.json defekt "
                                     f"({type(exc).__name__})")}
        if not isinstance(data, dict):
            return {"warn": warn.add(f"yellow {case_id}: orchestrator.json ohne Objekt")}
        steps = data.get("steps") if isinstance(data.get("steps"), dict) else {}
        fnd = data.get("findings") if isinstance(data.get("findings"), dict) else {}
        nxt = data.get("next_steps") if isinstance(data.get("next_steps"), list) else []
        step_ok = {}
        for action, rec in list(steps.items())[:20]:
            step_ok[str(action)[:40]] = bool(rec.get("ok")) if isinstance(rec, dict) else None
        packer = fnd.get("packer")
        compact = {
            "is_pe": fnd.get("is_pe") if isinstance(fnd.get("is_pe"), bool) else None,
            "packer": [str(x)[:30] for x in packer][:10] if isinstance(packer, list) else [],
            "ghidra_functions": _as_int(fnd.get("ghidra_functions")),
            "strings_count": _as_int(fnd.get("strings_count")),
        }
        return {
            "steps": step_ok,
            "tools": sorted({_YELLOW_STEP_TOOLS.get(a, a) for a in step_ok}),
            "findings": {k: v for k, v in compact.items() if v not in (None, [])},
            "next_steps": [str(s.get("label") or s.get("action") or "")[:80]
                           for s in nxt[:3] if isinstance(s, dict)],
            "updated_at": str(data.get("updated_at") or "")[:40],
        }
    return {}


def _load_yellow_brain_nodes(yellow_db_path: Optional[str] = None,
                             case_root=None, limit: int = YELLOW_CASE_CAP,
                             warn: Optional[_Warn] = None) -> dict:
    """Read-only Loader: yellow.db (cases/hops) + Case-Ordner/orchestrator.json
    → kompakte ``yellow_case``-Knoten. yellow.db bleibt Source of Truth und
    wird NIE geschrieben (sqlite mode=ro). Fehlende DB, fehlende Tabellen oder
    defektes orchestrator.json → leere Liste bzw. Warn-Feld, kein Abbruch.

    Rückgabe: {"status": ok|missing|error, "db_path", "nodes": [...], "warnings"}"""
    import sqlite3
    from . import yellow_bridge as _yb
    warn = warn or _Warn()
    path = _yb.yellow_db_path(yellow_db_path)
    res = {"status": "missing", "db_path": path, "nodes": [], "warnings": warn.items}
    try:
        conn = _open_yellow_ro(path)
    except sqlite3.Error as exc:
        warn.add(f"yellow.db nicht lesbar ({type(exc).__name__})")
        res["status"] = "error"
        return res
    if conn is None:
        return res
    roots = _yellow_case_roots(case_root)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(cases)").fetchall()}
        if not cols:
            warn.add("yellow.db: Tabelle 'cases' fehlt")
            res["status"] = "ok"
            return res
        want = [c for c in ("id", "filename", "sha256", "size", "kind", "route",
                            "packed", "status", "dynamic", "case_path",
                            "created_at", "updated_at") if c in cols]
        order = "created_at DESC" if "created_at" in cols else "rowid DESC"
        rows = conn.execute(f"SELECT {', '.join(want)} FROM cases "
                            f"ORDER BY {order} LIMIT ?", (int(limit),)).fetchall()
        has_hops = bool(conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='hops'").fetchone())
        for row in rows:
            case_id = str(_row_get(row, "id", "") or "")
            if not case_id:
                warn.add("yellow.db: Case ohne id übersprungen")
                continue
            hop_count, tools, last_summary = 0, set(), ""
            if has_hops:
                try:
                    hops = conn.execute(
                        "SELECT idx, op, skill, summary_de FROM hops WHERE case_id=? "
                        "ORDER BY idx", (case_id,)).fetchall()
                    hop_count = len(hops)
                    for h in hops:
                        t = (_row_get(h, "skill", "") or _row_get(h, "op", "") or "").strip()
                        if t:
                            tools.add(t[:40])
                    if hops:
                        last_summary = str(_row_get(hops[-1], "summary_de", "") or "")
                except sqlite3.Error as exc:
                    warn.add(f"yellow {case_id}: hops nicht lesbar ({type(exc).__name__})")
            case_dir = str(_row_get(row, "case_path", "") or "")
            if not case_dir:
                safe = _YELLOW_CASE_ID_RE.sub("_", case_id)
                case_dir = next((os.path.join(r, safe) for r in roots
                                 if os.path.isdir(os.path.join(r, safe))), "")
            orch = _read_orchestrator_summary(case_dir, warn, case_id)
            tools.update(orch.get("tools") or [])
            summary = last_summary
            if not summary and orch.get("findings"):
                summary = ", ".join(f"{k}={v}" for k, v in orch["findings"].items())
            filename = str(_row_get(row, "filename", "") or "")
            node = {
                "id": f"yellow-case:{case_id}", "type": "yellow_case",
                "colony": "yellow", "case_id": case_id,
                "label": (filename or case_id)[:60],
                "status": str(_row_get(row, "status", "") or "") or "unbekannt",
                "severity": None,
                # yellow.db/cases hat KEINE Ziel-Spalte → target bleibt None;
                # Asset-Bezug = Proben-Datei + Hash (echte Spalten).
                "target": None,
                "asset": filename,
                "sha256": str(_row_get(row, "sha256", "") or ""),
                "kind": str(_row_get(row, "kind", "") or ""),
                "route": str(_row_get(row, "route", "") or ""),
                "summary": summary[:200],
                "tools": sorted(tools)[:20],
                "counts": {"hops": hop_count, "tools": len(tools)},
                "orchestrator": {k: v for k, v in orch.items() if k != "tools"},
                "source_of_truth": "yellow.db",
                "created_at": _row_get(row, "created_at", None),
            }
            if orch.get("warn"):
                node["warn"] = orch["warn"]
            res["nodes"].append(node)
        res["status"] = "ok"
    except sqlite3.Error as exc:
        warn.add(f"yellow.db Lesefehler ({type(exc).__name__}: {str(exc)[:120]})")
        res["status"] = "error"
    finally:
        conn.close()
    return res


# ------------------------- Brücken-Auswertung -------------------------
def _bridge_view(evidence: dict) -> dict:
    """Bridge-Felder, die bridge.remediate_and_recheck / close_finding am Fund
    persistieren (evidence): bridge_outcome, recheck (Blue verify_closed),
    red_verify (Re-Check-Lauf, parse_degraded, reproduced), apply /
    remediation_apply / remediation, source_parse."""
    if not isinstance(evidence, dict):
        return {}
    out: dict = {}
    oc = str(evidence.get("bridge_outcome") or "")
    if oc:
        out["outcome"] = oc
    rc = evidence.get("recheck")
    if isinstance(rc, dict) and rc:
        out["fix_action"] = str(rc.get("fix_action") or rc.get("title") or "")[:120]
        out["verify_method"] = str(rc.get("verify_method") or "")[:80]
        if rc.get("closed") is not None:
            out["blue_closed"] = bool(rc.get("closed"))
    for key in ("remediation_apply", "apply", "remediation"):
        ap = evidence.get(key)
        if isinstance(ap, dict) and ap:
            out["apply_source"] = key
            if "closed" in ap:
                out["apply_closed"] = bool(ap.get("closed"))
            if ap.get("applied") is False and ap.get("reason"):
                out["apply_reason"] = str(ap.get("reason"))[:80]
            break
    rv = evidence.get("red_verify")
    if isinstance(rv, dict) and rv:
        out["recheck_run_id"] = str(rv.get("run_id") or "")
        out["parse_degraded"] = bool(rv.get("parse_degraded"))
        if "reproduced" in rv:
            out["reproduced"] = rv.get("reproduced")
        if rv.get("recheck_kind"):
            out["recheck_kind"] = str(rv.get("recheck_kind"))[:40]
        if rv.get("note"):
            out["note"] = str(rv.get("note"))[:200]
        if rv.get("error"):
            out["recheck_error"] = str(rv.get("error"))[:160]
    sp = evidence.get("source_parse")
    if isinstance(sp, dict) and (sp.get("parse_status") or sp.get("parse_warning")):
        out["source_parse_status"] = str(sp.get("parse_status") or "")
    return out


def nodes_graph(store: Store, log_cap: int = 50,
                include_blue: Optional[bool] = True,
                include_yellow: bool = True,
                colonies: Optional[tuple] = None,
                yellow_db_path: Optional[str] = None,
                yellow_case_root: Optional[str] = None) -> dict:
    """Vollständiger Node-Graph: Targets, Runs, Findings, Soldaten, Blue-Läufe/
    -Funde/-Aktionen, Yellow-Cases + Brücken-Kanten.

    Reiner Lesezugriff aus dem echten Store (keine erfundenen Daten).

    include_blue: Default True → Brain zeigt Red (offensive) UND Blue.
      None → Setting ``brain.include_blue`` (Default "1"). False → nur offensive.
    include_yellow: Yellow-Cases aus yellow.db (read-only, mode=ro) einhängen.
    colonies: explizite Kolonie-Auswahl, z. B. ("offensive",), ("blue",),
      ("offensive", "blue", "yellow"); überschreibt include_blue/include_yellow.

    Kanten (dedupliziert über (from, to, kind)): target-run, target-finding,
    soldier-finding, source-finding, remediated_by, verified_by, rechecked_by,
    analyzed_by_yellow. Lese-/Parse-Fehler einzelner Zeilen landen im Feld
    ``warnings`` (bzw. ``warn`` am Knoten) statt den Aufbau abzubrechen."""
    from . import registry as registry_mod
    import sqlite3
    warn = _Warn()
    nodes: list[dict] = []
    node_ids: set[str] = set()
    es = _EdgeSet()

    def _add_node(n: dict) -> bool:
        if n["id"] in node_ids:
            return False
        node_ids.add(n["id"])
        nodes.append(n)
        return True

    if include_blue is None:
        include_blue = _setting_bool(store, "brain.include_blue", "1")
    cols = _norm_colonies(colonies, bool(include_blue), bool(include_yellow))
    show_off = "offensive" in cols
    show_blue = "blue" in cols
    show_yellow = "yellow" in cols

    def _colony_shown(c: str) -> bool:
        return (c == "blue" and show_blue) or (c != "blue" and show_off)

    targets = store.list_targets(include_archived=True)
    target_names: dict[int, str] = {}
    for t in targets:
        tid = int(t["id"])
        target_names[tid] = t["name"]
        runs = store.list_scan_runs(tid)
        _add_node({
            "id": f"target:{tid}", "type": "target", "label": t["name"],
            "status": "archiviert" if t["archived_at"] else "aktiv",
            "severity": None,
            "counts": {"findings": store.count_findings(tid), "runs": len(runs),
                       "scopes": store.count_scopes(tid)},
            "created_at": t["created_at"], "created_fmt": _fmt(t["created_at"]),
        })

    # ---- Läufe (scan_runs): offensive "run", Blue "blue_run" -------------
    # parent_finding_id eines Laufs = Re-Check/Remediation genau eines Funds.
    run_parent: list[tuple[str, int, str]] = []   # (run node id, finding id, colony)
    for r in store.list_scan_runs():
        rid = str(_row_get(r, "run_id", "") or "")
        if not rid:
            warn.add("scan_runs: Zeile ohne run_id übersprungen")
            continue
        meta = _safe_json(_row_get(r, "meta", ""), warn, f"scan_runs[{rid}].meta")
        if not isinstance(meta, dict):
            meta = {}
        colony = "blue" if (_is_blue_run_id(rid) or meta.get("colony") == "blue") else "offensive"
        if not _colony_shown(colony):
            continue
        nid = f"run:{rid}"
        tid = _as_int(_row_get(r, "target_id"))
        status = str(_row_get(r, "status", "") or "")
        pfid = _as_int(_row_get(r, "parent_finding_id")) or _as_int(meta.get("parent_finding_id"))
        node = {
            "id": nid, "type": "blue_run" if colony == "blue" else "run",
            "label": rid[:18], "run_id": rid,
            "status": _run_node_status(status),
            "raw_status": status, "severity": None,
            "running": status in _RUNNING,
            "colony": colony,
            "target_id": tid, "target": target_names.get(tid) if tid is not None else None,
            "run_group_id": str(_row_get(r, "run_group_id", "") or meta.get("run_group_id") or ""),
            "parent_finding_id": pfid,
            "source": "scan_runs",
            "counts": {"logs": store.count_run_steps(rid)},
            "started_at": _row_get(r, "started_at"), "started_fmt": _fmt(_row_get(r, "started_at")),
            "finished_at": _row_get(r, "finished_at"), "finished_fmt": _fmt(_row_get(r, "finished_at")),
        }
        _add_node(node)
        if tid is not None:
            es.add(f"target:{tid}", nid, "target-run")
        if pfid is not None:
            run_parent.append((nid, pfid, colony))

    # ---- Blue-Läufe ohne scan_runs-Zeile (z. B. lokaler Lauf ohne Target):
    # run_history (mode='blue' / run_id blue-…) und blue_job_runs -------------
    if show_blue:
        extra: list[tuple[str, object]] = []
        try:
            for h in store.list_run_history(limit=EXTRA_BLUE_RUN_CAP):
                if (str(_row_get(h, "mode", "")) == "blue"
                        or _is_blue_run_id(_row_get(h, "run_id", ""))):
                    extra.append(("run_history", h))
        except sqlite3.Error as exc:
            warn.add(f"run_history nicht lesbar ({type(exc).__name__})")
        try:
            for j in store.list_blue_job_runs(limit=EXTRA_BLUE_RUN_CAP):
                extra.append(("blue_job_runs", j))
        except sqlite3.Error as exc:
            warn.add(f"blue_job_runs nicht lesbar ({type(exc).__name__})")
        for src, h in extra:
            rid = str(_row_get(h, "run_id", "") or "")
            if not rid:
                continue   # Job-Lauf ohne Blue-Run-ID (z. B. skipped) → kein Lauf-Knoten
            nid = f"run:{rid}"
            if nid in node_ids:
                continue
            tid = _as_int(_row_get(h, "target_id"))
            status = str(_row_get(h, "status", "") or "")
            pfid = _as_int(_row_get(h, "parent_finding_id"))
            _add_node({
                "id": nid, "type": "blue_run", "label": rid[:18], "run_id": rid,
                "status": _run_node_status(status), "raw_status": status,
                "severity": None, "running": False, "colony": "blue",
                "target_id": tid,
                "target": (target_names.get(tid) if tid is not None
                           else (str(_row_get(h, "target_name", "") or "") or None)),
                "run_group_id": str(_row_get(h, "run_group_id", "") or ""),
                "parent_finding_id": pfid, "source": src,
                "counts": {"findings": _as_int(_row_get(h, "finding_count")) or 0},
                "started_at": _row_get(h, "started_at"),
                "started_fmt": _fmt(_row_get(h, "started_at")),
                "finished_at": _row_get(h, "finished_at"),
                "finished_fmt": _fmt(_row_get(h, "finished_at")),
            })
            if tid is not None:
                es.add(f"target:{tid}", nid, "target-run")
            if pfid is not None:
                run_parent.append((nid, pfid, "blue"))

    # ---- Funde: "finding" (offensive), "blue_finding", + "blue_action" ----
    all_findings = []
    evidence_of: dict[int, dict] = {}
    finding_meta: dict[int, dict] = {}
    for f in store.list_findings():
        fid = _as_int(_row_get(f, "id"))
        if fid is None:
            warn.add("findings: Zeile ohne id übersprungen")
            continue
        ev = _safe_json(_row_get(f, "evidence", ""), warn, f"findings[{fid}].evidence")
        if not isinstance(ev, dict):
            ev = {}
        colony = _finding_colony(f, ev)
        if not _colony_shown(colony):
            continue
        all_findings.append(f)
        evidence_of[fid] = ev
        finding_meta[fid] = {"colony": colony,
                             "dedup_key": str(_row_get(f, "dedup_key", "") or ""),
                             "run_id": str(_row_get(f, "run_id", "") or ""),
                             "category": str(_row_get(f, "category", "") or "")}
    soldier_seen: set[str] = set()
    shown_findings = all_findings[:FINDING_CAP]
    for f in shown_findings:
        fid = int(f["id"])
        ev = evidence_of.get(fid, {})
        fm = finding_meta[fid]
        nid = f"finding:{fid}"
        tid = _as_int(_row_get(f, "target_id"))
        agent = str(_row_get(f, "agent", "") or "") or "unbekannt"
        src_fid = _as_int(_row_get(f, "source_finding_id"))
        par_fid = _as_int(_row_get(f, "parent_finding_id"))
        colony = fm["colony"]
        bv = _bridge_view(ev)
        node = {
            "id": nid, "type": "blue_finding" if colony == "blue" else "finding",
            "label": str(_row_get(f, "title", "") or "")[:40],
            "status": str(_row_get(f, "status", "") or ""),
            "severity": _row_get(f, "severity"),
            "agent": agent, "colony": colony,
            "category": fm["category"],
            "target_id": tid, "target": target_names.get(tid) if tid is not None else None,
            "asset": str(_row_get(f, "asset", "") or ""),
            "run_id": fm["run_id"],
            "run_group_id": str(_row_get(f, "run_group_id", "") or ""),
            "dedup_key": fm["dedup_key"],
            "source_finding_id": src_fid,
            "parent_finding_id": par_fid,
            "false_positive": bool(_row_get(f, "false_positive", 0)),
            "counts": {},
            "created_at": _row_get(f, "created_at"),
            "created_fmt": _fmt(_row_get(f, "created_at")),
        }
        if bv.get("outcome"):
            node["bridge_outcome"] = bv["outcome"]
        if ev.get("parse_status") or ev.get("parse_warning"):
            node["parse_status"] = str(ev.get("parse_status") or "")
        _add_node(node)
        if tid is not None:
            es.add(f"target:{tid}", nid, "target-finding")
        es.add(f"soldier:{agent}", nid, "soldier-finding")
        if src_fid is not None:
            # Selbstschleife (bridge setzt source_finding_id=eigene id) wird verworfen.
            es.add(f"finding:{src_fid}", nid, "source-finding")
        soldier_seen.add(agent)
        # Blue-Aktion aus der Brücke (Fix-Plan/Apply + Re-Check am Fund)
        if show_blue and (bv.get("outcome") or bv.get("apply_source") or bv.get("fix_action")):
            aid = f"blue-action:{fid}"
            _add_node({
                "id": aid, "type": "blue_action", "colony": "blue",
                "label": (bv.get("fix_action") or f"Fix + Re-Check #{fid}")[:40],
                "status": bv.get("outcome") or str(_row_get(f, "status", "") or ""),
                "severity": None, "finding_id": fid,
                "target_id": tid, "target": node["target"],
                "run_id": fm["run_id"], "run_group_id": node["run_group_id"],
                "bridge": bv, "counts": {},
            })

    # ---- Beziehungs-Kanten (Brücke Red → Blue → Re-Check) -----------------
    key_to_fid: dict[str, int] = {}
    for fid, fm in finding_meta.items():
        if fm["dedup_key"] and fm["category"] != _RECHECK_CATEGORY:
            key_to_fid.setdefault(fm["dedup_key"], fid)
    for f in shown_findings:
        fid = int(f["id"])
        fm = finding_meta[fid]
        nid = f"finding:{fid}"
        ev = evidence_of.get(fid, {})
        # (a) Blue-Fund mit Verweis auf einen anderen Fund → remediated_by
        if fm["colony"] == "blue":
            for ref in (_as_int(_row_get(f, "source_finding_id")),
                        _as_int(_row_get(f, "parent_finding_id"))):
                if ref is not None and ref != fid:
                    es.add(f"finding:{ref}", nid, EDGE_REMEDIATED_BY, node_ids,
                           via="source_finding_id/parent_finding_id")
        # (b) Bridge-Aktion am Fund → remediated_by + verified_by (Re-Check-Lauf)
        bv = _bridge_view(ev)
        aid = f"blue-action:{fid}"
        if aid in node_ids:
            es.add(nid, aid, EDGE_REMEDIATED_BY, node_ids, via="bridge",
                   outcome=bv.get("outcome"))
            if bv.get("recheck_run_id"):
                es.add(aid, f"run:{bv['recheck_run_id']}", EDGE_VERIFIED_BY, node_ids,
                       outcome=bv.get("outcome"),
                       parse_degraded=bv.get("parse_degraded"),
                       reproduced=bv.get("reproduced"))
        if bv.get("recheck_run_id"):
            es.add(nid, f"run:{bv['recheck_run_id']}", EDGE_RECHECKED_BY, node_ids,
                   outcome=bv.get("outcome"), parse_degraded=bv.get("parse_degraded"),
                   reproduced=bv.get("reproduced"))
        # (c) Meta-Fund des engen Re-Checks (RecheckAnt): evidence.recheck_of
        if fm["category"] == _RECHECK_CATEGORY:
            of = str(ev.get("recheck_of") or "")
            target_fid = key_to_fid.get(of)
            if target_fid is None:
                target_fid = _as_int(_row_get(f, "parent_finding_id"))
            if target_fid is not None:
                es.add(f"finding:{target_fid}", nid, EDGE_RECHECKED_BY, node_ids,
                       reproduced=ev.get("reproduced"),
                       recheck_kind=str(ev.get("recheck_kind") or "") or None)
    # (d) Läufe mit parent_finding_id: Blue → remediated_by, offensiv → rechecked_by
    for run_nid, pfid, colony in run_parent:
        kind = EDGE_REMEDIATED_BY if colony == "blue" else EDGE_RECHECKED_BY
        es.add(f"finding:{pfid}", run_nid, kind, node_ids, via="parent_finding_id")

    # ---- Soldaten/Capabilities aus der Registry ---------------------------
    try:
        reg = registry_mod.build_registry(include_blue=show_blue)
        for s in reg.get("soldiers", []):
            name = s.get("name", "")
            is_blue = _is_blue_agent(name) or s.get("colony") == "blue"
            if (is_blue and not show_blue) or (not is_blue and not show_off):
                continue
            fcount = sum(1 for f in all_findings if (_row_get(f, "agent", "") or "") == name)
            _add_node({
                "id": f"soldier:{name}", "type": "soldier", "label": name,
                "status": "aktiv", "severity": None,
                "colony": "blue" if is_blue else "offensive",
                "counts": {"findings": fcount,
                           "playbooks": len(s.get("skill", {}).get("playbooks", []))},
            })
            soldier_seen.discard(name)
    except Exception as exc:
        warn.add(f"Registry nicht lesbar ({type(exc).__name__})")
    for name in sorted(soldier_seen):
        if _is_blue_agent(name) and not show_blue:
            continue
        _add_node({"id": f"soldier:{name}", "type": "soldier", "label": name,
                   "status": "aktiv", "severity": None,
                   "colony": "blue" if _is_blue_agent(name) else "offensive",
                   "counts": {}})

    stuck = []
    for r in store.list_stuck_runs():
        rid = str(r["run_id"])
        if _colony_shown("blue" if _is_blue_run_id(rid) else "offensive"):
            stuck.append(rid)

    # ---- Yellow (read-only) ----------------------------------------------
    yellow_count, yellow_status = 0, "disabled"
    if show_yellow:
        yres = _load_yellow_brain_nodes(yellow_db_path, yellow_case_root,
                                        limit=max(10, min(log_cap, YELLOW_CASE_CAP)),
                                        warn=warn)
        yellow_status = yres["status"]
        by_sha: dict[str, str] = {}
        by_case: dict[str, str] = {}
        for yn in yres["nodes"]:
            if _add_node(yn):
                yellow_count += 1
                if yn.get("sha256"):
                    by_sha.setdefault(yn["sha256"].lower(), yn["id"])
                by_case[yn["case_id"]] = yn["id"]
        # analyzed_by_yellow: nur echte Bezüge – Fund-Evidence mit sha256 eines
        # Yellow-Case (z. B. Blue-AV-Quarantäne) oder run_id/run_group_id = case_id.
        if by_sha or by_case:
            for f in shown_findings:
                fid = int(f["id"])
                ev = evidence_of.get(fid, {})
                sha = str(ev.get("sha256") or "").lower()
                if sha and sha in by_sha:
                    es.add(f"finding:{fid}", by_sha[sha], EDGE_ANALYZED_BY_YELLOW,
                           node_ids, via="sha256")
                for ref in (finding_meta[fid]["run_id"],
                            str(_row_get(f, "run_group_id", "") or "")):
                    if ref and ref in by_case:
                        es.add(f"finding:{fid}", by_case[ref], EDGE_ANALYZED_BY_YELLOW,
                               node_ids, via="run_id/run_group_id")
            for n in nodes:
                if n.get("type") in ("run", "blue_run"):
                    for ref in (n.get("run_id"), n.get("run_group_id")):
                        if ref and ref in by_case:
                            es.add(n["id"], by_case[ref], EDGE_ANALYZED_BY_YELLOW,
                                   node_ids, via="run_id/run_group_id")

    edge_kinds: dict[str, int] = {}
    for e in es.edges:
        edge_kinds[e["kind"]] = edge_kinds.get(e["kind"], 0) + 1
    type_counts: dict[str, int] = {}
    for n in nodes:
        type_counts[n["type"]] = type_counts.get(n["type"], 0) + 1
    counts = {
        "targets": len(targets),
        "runs": len(store.list_scan_runs()),
        "findings": store.count_findings(),
        "logs": store.count_logs(),
        "stuck_runs": len(stuck),
        "yellow_cases": yellow_count,
        "yellow_status": yellow_status,
        "blue_runs": type_counts.get("blue_run", 0),
        "blue_findings": type_counts.get("blue_finding", 0),
        "blue_actions": type_counts.get("blue_action", 0),
        "edges_by_kind": edge_kinds,
        "edges_skipped_missing_node": es.skipped_missing,
        "warnings": warn.total,
        "include_blue": show_blue,
        "include_yellow": show_yellow,
        "colonies": list(cols),
    }
    return {"nodes": nodes, "edges": es.edges, "counts": counts,
            "stuck_runs": stuck, "warnings": list(warn.items),
            "generated_fmt": _fmt(time.time())}


def node_detail(store: Store, ntype: str, nid: str) -> dict:
    """Detail für einen Node inkl. zugehöriger Logs/Evidence. Reiner Lesezugriff."""
    import json as _json
    if ntype == "target":
        t = store.get_target(int(nid))
        if not t:
            return {"ok": False, "reason": "not_found"}
        findings = [dict(f) for f in store.list_findings(int(nid))]
        runs = [dict(r) for r in store.list_scan_runs(int(nid))]
        return {"ok": True, "type": "target", "target": dict(t),
                "finding_count": len(findings),
                "findings": [{"id": f["id"], "title": f["title"],
                              "severity": f["severity"], "status": f["status"],
                              "agent": f["agent"], "asset": f["asset"]}
                             for f in findings[:100]],
                "runs": [{"run_id": r["run_id"], "status": r["status"],
                          "started_fmt": _fmt(r["started_at"])} for r in runs]}
    if ntype == "run":
        r = store.get_scan_run(nid)
        if not r:
            return {"ok": False, "reason": "not_found"}
        logs = store.list_logs(run_id=nid, limit=500)
        return {"ok": True, "type": "run", "run": dict(r),
                "running": r["status"] in _RUNNING,
                "status_label": _run_node_status(r["status"]),
                "log_count": store.count_logs(run_id=nid),
                "logs": [_log_row(l) for l in logs]}
    if ntype == "finding":
        f = store.get_finding(int(nid))
        if not f:
            return {"ok": False, "reason": "not_found"}
        d = dict(f)
        try:
            d["evidence"] = _json.loads(d.get("evidence") or "{}")
        except Exception:
            pass
        logs = store.list_logs(run_id=f["run_id"], limit=200)
        d["created_fmt"] = _fmt(f["created_at"])
        return {"ok": True, "type": "finding", "finding": d,
                "logs": [_log_row(l) for l in logs]}
    if ntype == "soldier":
        # Default wie nodes_graph: Blue sichtbar; brain.include_blue=0 schließt aus.
        allow_blue = _setting_bool(store, "brain.include_blue", "1")
        if _is_blue_agent(nid) and not allow_blue:
            return {"ok": False, "reason": "blue_queen_separate",
                    "hint": "Blue Queen hat eigene Ansicht unter /blue "
                            "(Schalter brain.include_blue=1 öffnet Brain-Ansicht)"}
        findings = [f for f in store.list_findings()
                    if (f["agent"] or "") == nid and (allow_blue or not _is_blue_run_id(
                        f["run_id"] if "run_id" in f.keys() else None))]
        # Playbooks + SKILL.md aus der Capability-Registry (Single Source of Truth).
        # Ohne diese Anreicherung sah die Brain-Detailansicht nur Funde — Judith
        # meldete „keinerlei Playbooks einsehbar“.
        role = specialty = ""
        colony = None
        playbooks: list = []
        skill: dict = {}
        try:
            from . import registry as _reg
            sol = next((s for s in _reg.build_registry(include_blue=allow_blue)["soldiers"]
                        if s.get("name") == nid), None)
            if sol:
                role = sol.get("role") or ""
                specialty = sol.get("specialty") or ""
                colony = sol.get("colony")
                playbooks = list(sol.get("playbooks") or [])
                skill = dict(sol.get("skill") or {})
        except Exception:
            pass
        return {"ok": True, "type": "soldier", "name": nid,
                "role": role, "specialty": specialty, "colony": colony,
                "playbooks": playbooks, "skill": skill,
                "playbook_count": len(playbooks),
                "finding_count": len(findings),
                "findings": [{"id": f["id"], "title": f["title"],
                              "severity": f["severity"], "status": f["status"],
                              "target_id": f["target_id"]} for f in findings[:100]]}
    if ntype == "blue-action":
        # Bridge-Aktion (Fix-Plan/Apply + Re-Check) am Fund – nur Lesen.
        fid = _as_int(nid)
        f = store.get_finding(fid) if fid is not None else None
        if not f:
            return {"ok": False, "reason": "not_found"}
        warn = _Warn()
        ev = _safe_json(f["evidence"], warn, f"findings[{fid}].evidence")
        bv = _bridge_view(ev if isinstance(ev, dict) else {})
        if not bv:
            return {"ok": False, "reason": "no_bridge_action"}
        return {"ok": True, "type": "blue_action", "finding_id": fid,
                "finding": {"id": fid, "title": f["title"], "status": f["status"],
                            "severity": f["severity"], "asset": f["asset"],
                            "target_id": f["target_id"]},
                "bridge": bv, "warnings": warn.items}
    if ntype == "yellow-case":
        # Kompakter Yellow-Case aus yellow.db (read-only) – keine Roh-Dumps.
        res = _load_yellow_brain_nodes(limit=500)
        node = next((n for n in res["nodes"] if n.get("case_id") == nid), None)
        if node is None:
            return {"ok": False, "reason": "not_found", "yellow_status": res["status"]}
        return {"ok": True, "type": "yellow_case", "case": node,
                "warnings": res["warnings"]}
    return {"ok": False, "reason": "unknown_type"}


def _log_row(l) -> dict:
    import json as _json
    try:
        payload = _json.loads(l["payload"] or "{}")
    except Exception:
        payload = {}
    return {"id": l["id"], "run_id": l["run_id"], "seq": l["seq"],
            "phase": l["phase"], "agent": l["agent"], "kind": l["kind"],
            "target_id": l["target_id"] if "target_id" in l.keys() else None,
            "msg": payload.get("msg", ""), "payload": payload,
            "created_at": l["created_at"], "created_fmt": _fmt(l["created_at"])}


def logs_page(store: Store, target_id: Optional[int] = None,
              run_id: Optional[str] = None, limit: int = 200,
              offset: int = 0) -> dict:
    """Vollständige Logs (scan_steps), neueste zuerst, filter-/paginierbar."""
    limit = max(1, min(int(limit), 1000))
    rows = store.list_logs(target_id=target_id, run_id=run_id,
                           limit=limit, offset=int(offset))
    total = store.count_logs(target_id=target_id, run_id=run_id)
    return {"logs": [_log_row(l) for l in rows], "total": total,
            "limit": limit, "offset": int(offset),
            "target_id": target_id, "run_id": run_id}


# ===================================================================
# HUMAN-ONLY: Löschen / Reset  (jede Funktion verlangt human_confirm=True)
# ===================================================================
def delete_logs(store: Store, *, human_confirm, target_id: Optional[int] = None,
                run_id: Optional[str] = None, all_logs: bool = False,
                actor: str = "web-ui") -> dict:
    """Löscht Log-Zeilen (scan_steps). Human-only (siehe Modul-Kopf)."""
    _require_human(store, human_confirm, "delete_logs")
    backup = backup_db(store)
    n = store.purge_logs(target_id=target_id, run_id=run_id, all_logs=all_logs)
    _audit(store, f"DELETE logs · actor={actor} · target={target_id} · "
                  f"run={run_id} · all={all_logs} · deleted={n} · backup={os.path.basename(backup)}")
    return {"ok": True, "deleted": {"logs": n}, "backup": backup}


def delete_run(store: Store, run_id: str, *, human_confirm,
               actor: str = "web-ui") -> dict:
    """Löscht EINEN Lauf samt Log-Zeilen (CASCADE). Human-only."""
    _require_human(store, human_confirm, "delete_run")
    backup = backup_db(store)
    steps = store.count_run_steps(run_id)
    existed = store.get_scan_run(run_id) is not None
    store.delete_scan_run(run_id)
    _audit(store, f"DELETE run · actor={actor} · run={run_id} · "
                  f"steps={steps} · existed={existed} · backup={os.path.basename(backup)}")
    return {"ok": existed, "deleted": {"runs": 1 if existed else 0,
            "logs": steps}, "backup": backup}


def delete_finding(store: Store, finding_id: int, *, human_confirm,
                   actor: str = "web-ui") -> dict:
    """Löscht EIN Finding. Human-only."""
    _require_human(store, human_confirm, "delete_finding")
    backup = backup_db(store)
    n = store.delete_finding(finding_id)
    _audit(store, f"DELETE finding · actor={actor} · id={finding_id} · "
                  f"deleted={n} · backup={os.path.basename(backup)}")
    return {"ok": bool(n), "deleted": {"findings": n}, "backup": backup}


def delete_target(store: Store, target_id: int, *, human_confirm,
                  actor: str = "web-ui") -> dict:
    """HARTE Löschung (Purge) EINES Targets samt CASCADE (Scopes/Findings/
    Reports/Scan-Historie/Oversight). Unterscheidet sich ausdrücklich vom
    Soft-Delete/Papierkorb (archive_target). Königin-Wissen (Registry/Mems/
    Overrides) bleibt erhalten. Human-only."""
    _require_human(store, human_confirm, "delete_target")
    backup = backup_db(store)
    t = store.get_target(int(target_id))
    label = t["name"] if t else ""
    fcount = store.count_findings(int(target_id)) if t else 0
    store.delete_target(int(target_id))
    _audit(store, f"DELETE target (HARD purge) · actor={actor} · id={target_id} · "
                  f"name={label} · findings={fcount} · backup={os.path.basename(backup)}")
    return {"ok": bool(t), "deleted": {"targets": 1 if t else 0,
            "findings": fcount, "name": label}, "backup": backup}


def delete_all(store: Store, *, human_confirm, actor: str = "web-ui") -> dict:
    """Wischt ALLE operativen Daten. Königin-Wissen bleibt erhalten. Human-only."""
    _require_human(store, human_confirm, "delete_all")
    backup = backup_db(store)
    counts = store.wipe_operational()
    _audit(store, f"DELETE ALL (operational wipe) · actor={actor} · "
                  f"counts={counts} · backup={os.path.basename(backup)}")
    return {"ok": True, "deleted": counts, "backup": backup,
            "preserved": ["capabilities", "soldier_mems", "soldier_overrides",
                          "settings"]}


def reset_run(store: Store, run_id: str, *, human_confirm,
              actor: str = "web-ui") -> dict:
    """Setzt einen laufenden/hängenden Lauf zurück (Status 'reset', unfertige
    scan_steps verworfen). Fertige Läufe/Funde/Königin-Wissen bleiben
    unangetastet. Human-only."""
    _require_human(store, human_confirm, "reset_run")
    backup = backup_db(store)
    res = store.reset_scan_run(run_id)
    res["backup"] = backup
    _audit(store, f"RESET run · actor={actor} · run={run_id} · "
                  f"result={res.get('ok')}/{res.get('reason','')} · "
                  f"steps_discarded={res.get('steps_discarded')} · "
                  f"backup={os.path.basename(backup)}")
    return res
