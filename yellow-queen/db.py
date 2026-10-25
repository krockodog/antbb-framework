"""SQLite-Persistenz (data/yellow.db). Jeder Datensatz trägt queen_id='yellow' (swarm-merge-freundlich)."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, queen_id TEXT NOT NULL DEFAULT 'yellow',
  filename TEXT, sha256 TEXT, size INTEGER, kind TEXT, route TEXT,
  packed INTEGER DEFAULT 0, status TEXT, dynamic TEXT, authorized INTEGER,
  oversight INTEGER, case_path TEXT, classification_json TEXT,
  created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS hops (
  id INTEGER PRIMARY KEY AUTOINCREMENT, queen_id TEXT NOT NULL DEFAULT 'yellow',
  case_id TEXT NOT NULL, idx INTEGER, op TEXT, skill TEXT, status TEXT,
  summary_de TEXT, warum TEXT, fund TEXT, next TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS brain_snapshots (
  case_id TEXT PRIMARY KEY, queen_id TEXT NOT NULL DEFAULT 'yellow',
  snapshot_json TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, queen_id TEXT NOT NULL DEFAULT 'yellow',
  case_id TEXT, kind TEXT, message TEXT, ts TEXT);
"""


@contextmanager
def conn() -> Iterator[sqlite3.Connection]:
    config.ensure_dirs()
    c = sqlite3.connect(config.DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        c.executescript(SCHEMA)
        yield c
        c.commit()
    finally:
        c.close()


def insert_case(row: dict[str, Any]) -> None:
    row = {**row, "queen_id": "yellow"}
    cols = ",".join(row)
    qs = ",".join("?" for _ in row)
    with conn() as c:
        c.execute(f"INSERT OR REPLACE INTO cases ({cols}) VALUES ({qs})", list(row.values()))


def update_case(case_id: str, **fields: Any) -> None:
    fields["updated_at"] = config.now_iso()
    sets = ",".join(f"{k}=?" for k in fields)
    with conn() as c:
        c.execute(f"UPDATE cases SET {sets} WHERE id=?", [*fields.values(), case_id])


def add_hop(case_id: str, idx: int, hop: dict[str, Any]) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO hops (queen_id,case_id,idx,op,skill,status,summary_de,warum,fund,next,ts) VALUES ('yellow',?,?,?,?,?,?,?,?,?,?)",
            (case_id, idx, hop["op"], hop.get("skill", ""), hop.get("status", "ok"), hop["summary_de"],
             hop.get("warum", ""), hop.get("fund", ""), json.dumps(hop.get("next", []), ensure_ascii=False), config.now_iso()))


def add_event(case_id: str | None, kind: str, message: str) -> None:
    with conn() as c:
        c.execute("INSERT INTO events (queen_id,case_id,kind,message,ts) VALUES ('yellow',?,?,?,?)",
                  (case_id, kind, message, config.now_iso()))


def save_snapshot(case_id: str, snap: dict[str, Any]) -> None:
    with conn() as c:
        c.execute("INSERT OR REPLACE INTO brain_snapshots (case_id,queen_id,snapshot_json,updated_at) VALUES (?,?,?,?)",
                  (case_id, "yellow", json.dumps(snap, ensure_ascii=False), config.now_iso()))


def load_snapshot(case_id: str) -> dict[str, Any] | None:
    with conn() as c:
        r = c.execute("SELECT snapshot_json FROM brain_snapshots WHERE case_id=?", (case_id,)).fetchone()
    return json.loads(r["snapshot_json"]) if r else None


def get_case(case_id: str) -> dict[str, Any] | None:
    with conn() as c:
        r = c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        hops = [dict(h) for h in c.execute("SELECT * FROM hops WHERE case_id=? ORDER BY idx", (case_id,))]
    for h in hops:
        h["next"] = json.loads(h["next"] or "[]")
    d["hops"] = hops
    return d


def list_cases(limit: int = 100) -> list[dict[str, Any]]:
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT id,queen_id,filename,sha256,size,kind,route,packed,status,dynamic,created_at FROM cases ORDER BY created_at DESC LIMIT ?",
            (limit,))]


def latest_case_id() -> str | None:
    with conn() as c:
        r = c.execute("SELECT id FROM cases ORDER BY created_at DESC, rowid DESC LIMIT 1").fetchone()
    return r["id"] if r else None
