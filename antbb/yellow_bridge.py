"""Read-only Brücke: yellow.db / Case-Artefakte → gemeinsamer Brain-Kontext.

yellow.db bleibt Source of Truth. Dieses Modul liest nur und liefert
Referenzen/Zusammenfassungen für den Wissensgraphen (brain_ops).
"""
from __future__ import annotations

import json
import os
import sqlite3
from typing import Any, Optional


def _default_yellow_db() -> str:
    # Parallel zur antbb-DB unter data/, wie yellow-queen/config es erwartet.
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "data", "yellow.db")


def yellow_db_path(explicit: Optional[str] = None) -> str:
    return explicit or os.environ.get("ANTBB_YELLOW_DB") or _default_yellow_db()


def _connect(path: str) -> Optional[sqlite3.Connection]:
    if not path or not os.path.isfile(path):
        return None
    try:
        c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        c.row_factory = sqlite3.Row
        return c
    except Exception:
        return None


def list_yellow_summaries(limit: int = 50, db_path: Optional[str] = None) -> list[dict]:
    """Liest Cases + letzte Hops/Events als Brain-Knoten-taugliche Summaries.

    Nur echte DB-Zeilen; keine erfundenen Funde. Bei fehlender DB → [].
    """
    path = yellow_db_path(db_path)
    conn = _connect(path)
    if conn is None:
        return []
    out: list[dict] = []
    try:
        cases = conn.execute(
            "SELECT id, queen_id, filename, sha256, size, kind, route, packed, "
            "status, dynamic, case_path, created_at FROM cases "
            "ORDER BY created_at DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        for row in cases:
            d = dict(row)
            case_id = d.get("id")
            hops = []
            try:
                hops = [dict(h) for h in conn.execute(
                    "SELECT idx, op, skill, status, summary_de, fund, ts "
                    "FROM hops WHERE case_id=? ORDER BY idx LIMIT 40",
                    (case_id,),
                ).fetchall()]
            except Exception:
                hops = []
            tools_seen = sorted({
                (h.get("skill") or h.get("op") or "").strip()
                for h in hops if (h.get("skill") or h.get("op"))
            })
            # Bekannte RE-Tools markieren (nur Label, keine Extraktion)
            known = {"diec", "upx", "analyzeHeadless", "ghidra-mcp", "ghidra",
                     "die", "diec.exe", "strings", "capa"}
            tool_hits = [t for t in tools_seen if any(k.lower() in t.lower() for k in known)]
            orch = _read_orchestrator_json(d.get("case_path") or "")
            out.append({
                "id": f"yellow-case:{case_id}",
                "type": "yellow_case",
                "label": (d.get("filename") or case_id or "")[:60],
                "status": d.get("status") or "",
                "kind": d.get("kind") or "",
                "route": d.get("route") or "",
                "case_id": case_id,
                "sha256": d.get("sha256") or "",
                "tools": tools_seen,
                "tool_hits": tool_hits,
                "hop_count": len(hops),
                "hop_summaries": [
                    {"idx": h.get("idx"), "op": h.get("op"), "skill": h.get("skill"),
                     "status": h.get("status"), "summary": (h.get("summary_de") or "")[:200],
                     "fund": (h.get("fund") or "")[:200]}
                    for h in hops[:20]
                ],
                "orchestrator_refs": orch,
                "source_of_truth": path,
                "created_at": d.get("created_at"),
            })
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return out


def _read_orchestrator_json(case_path: str) -> dict:
    """Liest orchestrator.json neben dem Case, falls vorhanden (read-only)."""
    if not case_path:
        return {}
    candidates = [
        os.path.join(case_path, "orchestrator.json"),
        os.path.join(case_path, "state", "orchestrator.json"),
    ]
    for p in candidates:
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return {"path": p, "note": "non-dict"}
            # Nur Referenzen/Keys, keine Roh-Binärdaten
            keys = sorted(data.keys())
            return {
                "path": p,
                "keys": keys[:40],
                "status": data.get("status") or data.get("state") or "",
                "last_skill": data.get("last_skill") or data.get("skill") or "",
                "summary": str(data.get("summary") or data.get("summary_de") or "")[:300],
            }
        except Exception as exc:
            return {"path": p, "error": f"{type(exc).__name__}: {exc}"}
    return {}


def yellow_graph_nodes(limit: int = 50, db_path: Optional[str] = None) -> tuple[list, list]:
    """Nodes + Edges für brain_ops.nodes_graph (Yellow-Anteil)."""
    nodes: list[dict] = []
    edges: list[dict] = []
    for s in list_yellow_summaries(limit=limit, db_path=db_path):
        nid = s["id"]
        nodes.append({
            "id": nid, "type": "yellow_case", "label": s["label"],
            "status": s["status"], "severity": None,
            "counts": {"hops": s["hop_count"], "tools": len(s.get("tools") or [])},
            "meta": {
                "kind": s.get("kind"), "route": s.get("route"),
                "tool_hits": s.get("tool_hits"), "sha256": s.get("sha256"),
                "source_of_truth": s.get("source_of_truth"),
                "orchestrator_refs": s.get("orchestrator_refs") or {},
            },
            "created_at": s.get("created_at"),
        })
        for h in (s.get("hop_summaries") or [])[:10]:
            hid = f"yellow-hop:{s['case_id']}:{h.get('idx')}"
            nodes.append({
                "id": hid, "type": "yellow_hop",
                "label": (h.get("skill") or h.get("op") or "hop")[:40],
                "status": h.get("status") or "",
                "severity": None,
                "counts": {},
                "meta": {"summary": h.get("summary"), "fund": h.get("fund")},
            })
            edges.append({"from": nid, "to": hid, "kind": "yellow-case-hop"})
    return nodes, edges
