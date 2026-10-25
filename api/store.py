"""SQLite-Kolonie plus Dossier und Ledger auf der Platte. Je Königin ein Raum."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from api.catalog import (
    COLOR_WORD,
    DESCRIPTION,
    FOOTER,
    FORBIDDEN_PLAYBOOK,
    PLAYBOOKS,
    PRODUCT,
    QUEEN_IDS,
    QUEENS,
    SOLDIERS,
    playbook_map,
    soldier_map,
)
from api.classify import classify

_RUN_ID = re.compile(r"^[a-f0-9]{32}$")


class ColonyError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass
class Settings:
    db_path: Path
    data_dir: Path
    run_limit: int = 8
    run_window_s: float = 60.0
    classify_limit: int = 30
    classify_window_s: float = 60.0

    @classmethod
    def from_env(cls) -> Settings:
        import os

        root = Path(__file__).resolve().parents[1]
        db = Path(os.environ.get("COLONY_DB", root / "data" / "colony.sqlite"))
        data = Path(os.environ.get("COLONY_DATA", root / "data" / "runs"))
        return cls(db_path=db, data_dir=data)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _clean_allow(raw: list[str]) -> list[str]:
    if len(raw) > 32:
        raise ColonyError(400, "Die Allowlist ist zu lang. Ich nehme höchstens 32 Ziele.")
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in raw:
        value = item.strip()
        if not value:
            continue
        if len(value) > 120:
            raise ColonyError(400, "Ein Ziel ist länger als 120 Zeichen.")
        if any(mark in value for mark in ("*", "\n", "\r", " ")):
            raise ColonyError(400, "Ein Stern oder Leerzeichen ist keine Allowlist.")
        if value not in seen:
            seen.add(value)
            cleaned.append(value)
    return cleaned


class Store:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.settings.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.settings.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._runs_at: dict[str, list[float]] = {queen: [] for queen in QUEEN_IDS}
        self._classify_at: list[float] = []
        self._init_db()

    def close(self) -> None:
        self._conn.close()

    def _init_db(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scope (
              queen_id TEXT PRIMARY KEY,
              allow_json TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oversight (
              queen_id TEXT PRIMARY KEY,
              armed INTEGER NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS soldier_state (
              queen_id TEXT NOT NULL,
              soldier_id TEXT NOT NULL,
              mode TEXT NOT NULL,
              tut TEXT NOT NULL,
              live_satz TEXT NOT NULL,
              PRIMARY KEY (queen_id, soldier_id)
            );
            CREATE TABLE IF NOT EXISTS runs (
              run_id TEXT PRIMARY KEY,
              queen_id TEXT NOT NULL,
              soldier_id TEXT NOT NULL,
              playbook_id TEXT NOT NULL,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL,
              summary TEXT NOT NULL,
              dossier_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ledger (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              queen_id TEXT NOT NULL,
              run_id TEXT NOT NULL,
              at TEXT NOT NULL,
              message TEXT NOT NULL
            );
            """
        )
        now = _now()
        for queen in QUEEN_IDS:
            self._conn.execute(
                "INSERT OR IGNORE INTO scope (queen_id, allow_json, updated_at) VALUES (?, '[]', ?)",
                (queen, now),
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO oversight (queen_id, armed, updated_at) VALUES (?, 0, ?)",
                (queen, now),
            )
            for soldier in SOLDIERS[queen]:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO soldier_state
                      (queen_id, soldier_id, mode, tut, live_satz)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        queen,
                        soldier["soldier_id"],
                        soldier["mode"],
                        soldier["tut"],
                        soldier["live_satz"],
                    ),
                )
        self._conn.commit()

    def _allow(self, queen_id: str) -> list[str]:
        row = self._conn.execute(
            "SELECT allow_json FROM scope WHERE queen_id = ?", (queen_id,)
        ).fetchone()
        return json.loads(row["allow_json"]) if row else []

    def _armed(self, queen_id: str) -> bool:
        row = self._conn.execute(
            "SELECT armed FROM oversight WHERE queen_id = ?", (queen_id,)
        ).fetchone()
        return bool(row["armed"]) if row else False

    def _soldier_row(self, queen_id: str, soldier_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT mode, tut, live_satz FROM soldier_state
            WHERE queen_id = ? AND soldier_id = ?
            """,
            (queen_id, soldier_id),
        ).fetchone()

    def _public_soldier(self, queen_id: str, seed: dict) -> dict:
        state = self._soldier_row(queen_id, seed["soldier_id"])
        books = playbook_map(queen_id)
        return {
            "queen_id": queen_id,
            "soldier_id": seed["soldier_id"],
            "name": seed["name"],
            "role": seed["role"],
            "mode": state["mode"] if state else seed["mode"],
            "tut": state["tut"] if state else seed["tut"],
            "live_satz": state["live_satz"] if state else seed["live_satz"],
            "playbook_ids": list(seed["playbook_ids"]),
            "playbooks": [
                self._public_playbook(queen_id, books[pid]) for pid in seed["playbook_ids"]
            ],
            "oversight_required": seed["oversight_required"],
            "stub": True,
            "stub_note": seed["stub_note"],
        }

    def _public_playbook(self, queen_id: str, seed: dict) -> dict:
        return {
            "queen_id": queen_id,
            "playbook_id": seed["playbook_id"],
            "title": seed["title"],
            "kind": seed["kind"],
            "summary": seed["summary"],
            "destructive": bool(seed["destructive"]),
            "requires_oversight": True,
            "stub": True,
            "stub_note": seed["stub_note"],
            "needs_probe": seed["needs_probe"],
        }

    def queen_summary(self, queen_id: str) -> dict:
        with self._lock:
            summary = self._queen_summary_locked(queen_id)
        try:
            from api.real_queens import enrich_summary
            return enrich_summary(summary)
        except Exception:
            summary = dict(summary)
            summary["soldier_ids"] = []
            summary["live_satz"] = "Live-Status wird aus der Kolonie gelesen…"
            return summary

    def _queen_summary_locked(self, queen_id: str) -> dict:
        seed = QUEENS[queen_id]
        soldiers = [self._public_soldier(queen_id, item) for item in SOLDIERS[queen_id]]
        active = next((item for item in soldiers if item["mode"] == "lauf"), None)
        tut = active["tut"] if active else seed["tut"]
        live = active["live_satz"] if active else seed["live_satz"]
        return {
            "queen_id": queen_id,
            "name": seed["name"],
            "kicker": seed["kicker"],
            "summary": seed["summary"],
            "cta": seed["cta"],
            "href": seed["href"],
            "tut": tut,
            "strip_teil": f"{COLOR_WORD[queen_id]} tut {tut}",
            "live_satz": live,
            "oversight": self._armed(queen_id),
            "scope": self._allow(queen_id),
            "soldier_ids": [item["soldier_id"] for item in soldiers],
            "playbook_ids": [item["playbook_id"] for item in PLAYBOOKS[queen_id]],
        }

    def queen_detail(self, queen_id: str) -> dict:
        with self._lock:
            summary = self._queen_summary_locked(queen_id)
            summary["soldiers"] = [
                self._public_soldier(queen_id, item) for item in SOLDIERS[queen_id]
            ]
            summary["playbooks"] = [
                self._public_playbook(queen_id, item) for item in PLAYBOOKS[queen_id]
            ]
            summary["runs"] = self._runs_locked(queen_id)
            summary["ledger"] = self._ledger_locked(queen_id)
        if queen_id in ("red", "blue"):
            # Echte Soldaten aus der antbb-Registry; Fallback = Seed oben.
            try:
                from api.real_queens import enrich_summary, real_soldier_ids

                real_ids = real_soldier_ids(queen_id)
                if real_ids:
                    summary = enrich_summary(summary)
                    summary["soldier_ids"] = list(real_ids)
            except Exception:  # noqa: BLE001
                pass
        return summary

    def set_scope(self, queen_id: str, allow: list[str]) -> dict:
        cleaned = _clean_allow(allow)
        with self._lock:
            self._conn.execute(
                "UPDATE scope SET allow_json = ?, updated_at = ? WHERE queen_id = ?",
                (json.dumps(cleaned, ensure_ascii=False), _now(), queen_id),
            )
            self._conn.commit()
            return {
                "queen_id": queen_id,
                "mode": "default-deny",
                "allow": cleaned,
            }

    def set_oversight(self, queen_id: str, armed: bool) -> dict:
        with self._lock:
            self._conn.execute(
                "UPDATE oversight SET armed = ?, updated_at = ? WHERE queen_id = ?",
                (1 if armed else 0, _now(), queen_id),
            )
            self._conn.commit()
            return {"queen_id": queen_id, "armed": armed}

    def _runs_locked(self, queen_id: str) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT run_id, queen_id, soldier_id, playbook_id, status, created_at, summary
            FROM runs WHERE queen_id = ? ORDER BY created_at DESC LIMIT 40
            """,
            (queen_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def _ledger_locked(self, queen_id: str) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT queen_id, run_id, at, message FROM ledger
            WHERE queen_id = ? ORDER BY id DESC LIMIT 40
            """,
            (queen_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def list_runs(self, queen_id: str) -> list[dict]:
        with self._lock:
            return self._runs_locked(queen_id)

    def ledger(self, queen_id: str) -> list[dict]:
        with self._lock:
            return self._ledger_locked(queen_id)

    def get_run(self, queen_id: str, run_id: str) -> dict:
        if not _RUN_ID.fullmatch(run_id):
            raise ColonyError(404, "Diesen Lauf kenne ich nicht.")
        with self._lock:
            row = self._conn.execute(
                "SELECT dossier_json, queen_id FROM runs WHERE run_id = ? AND queen_id = ?",
                (run_id, queen_id),
            ).fetchone()
        if row is None:
            raise ColonyError(404, "Diesen Lauf kenne ich in dieser Kolonie nicht.")
        dossier = json.loads(row["dossier_json"])
        dossier["queen_id"] = queen_id
        return dossier

    def _hit(self, bucket: list[float], limit: int, window: float) -> bool:
        now = time.monotonic()
        bucket[:] = [stamp for stamp in bucket if now - stamp < window]
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True

    def _run_dir(self, queen_id: str, run_id: str) -> Path:
        root = self.settings.data_dir.resolve()
        path = (root / queen_id / run_id).resolve()
        if root != path.parent.parent or path.parent.name != queen_id:
            raise ColonyError(400, "Der Ablagepfad bleibt in der Kolonie.")
        return path

    def start_run(
        self,
        queen_id: str,
        soldier_id: str,
        playbook_id: str,
        oversight: bool,
        targets: list[str],
        probe_name: str | None,
    ) -> dict:
        lowered = playbook_id.lower()
        if any(token in lowered for token in FORBIDDEN_PLAYBOOK):
            raise ColonyError(
                403,
                "Das Playbook bleibt aus. Last, Raten und Angriffswerkzeug sind hier nicht vorgesehen.",
            )
        books = playbook_map(queen_id)
        soldiers = soldier_map(queen_id)
        playbook = books.get(playbook_id)
        if playbook is None:
            raise ColonyError(404, "Dieses Playbook gehört nicht zu dieser Königin.")
        if playbook["destructive"]:
            raise ColonyError(403, "Destruktive Playbooks sind aus.")
        soldier = soldiers.get(soldier_id)
        if soldier is None:
            raise ColonyError(404, "Diese Soldatin gehört nicht zu dieser Königin.")
        if playbook_id not in soldier["playbook_ids"]:
            raise ColonyError(403, "Diese Soldatin führt das Playbook nicht.")
        if not oversight:
            raise ColonyError(403, "Oversight fehlt. Aktive Arbeit bleibt aus.")
        cleaned_targets = _clean_allow(targets)
        if not cleaned_targets:
            raise ColonyError(403, "Scope ist leer. Default-deny lässt keinen Lauf zu.")
        if playbook["needs_probe"]:
            if not probe_name or not probe_name.strip():
                raise ColonyError(400, "Für diesen Lauf brauche ich einen Probenamen.")
            if len(probe_name.strip()) > 180:
                raise ColonyError(400, "Der Probename ist zu lang.")
        with self._lock:
            if not self._armed(queen_id):
                raise ColonyError(403, "Oversight ist nicht gesetzt. Ich starte den Lauf nicht.")
            allow = self._allow(queen_id)
            if not allow:
                raise ColonyError(403, "Scope ist leer. Default-deny lässt keinen Lauf zu.")
            outside = [target for target in cleaned_targets if target not in allow]
            if outside:
                raise ColonyError(403, "Ziel liegt außerhalb der Allowlist.")
            if not self._hit(self._runs_at[queen_id], self.settings.run_limit, self.settings.run_window_s):
                raise ColonyError(429, "Zu viele Läufe. Ich drossele, damit niemand Last erzeugt.")
            run_id = uuid.uuid4().hex
            created = _now()
            plan = None
            if queen_id == "yellow" and playbook["kind"] == "classify":
                plan = classify(probe_name or "", None, True)
            summary = (
                f"{soldier['name']} legt das Dossier für „{playbook['title']}“ ab. "
                f"{playbook['stub_note']}"
            )
            dossier = {
                "run_id": run_id,
                "queen_id": queen_id,
                "soldier_id": soldier_id,
                "soldier_name": soldier["name"],
                "playbook_id": playbook_id,
                "playbook_title": playbook["title"],
                "targets": cleaned_targets,
                "probe_name": probe_name.strip() if probe_name else None,
                "oversight": True,
                "status": "dossier",
                "stub": True,
                "stub_note": playbook["stub_note"],
                "summary": summary,
                "created_at": created,
                "plan": plan,
                "ledger_file": "ledger.jsonl",
            }
            folder = self._run_dir(queen_id, run_id)
            folder.mkdir(parents=True, exist_ok=False)
            # Echter Executor: echte Arbeit statt Dossier-Mock. Artefakte liegen
            # im Lauf-Ordner; das Dossier vermerkt stub:false + Belege ehrlich.
            from api import executors as _exec_mod
            evidence = _exec_mod.execute(
                queen_id, playbook_id, cleaned_targets,
                probe_name.strip() if probe_name else None, folder,
            )
            dossier["stub"] = False
            dossier.pop("stub_note", None)
            dossier["evidence"] = evidence
            dossier["summary"] = (
                f"{soldier['name']} führt „{playbook['title']}“ aus "
                f"({evidence.get('executor', 'executor')}): "
                f"{evidence.get('note') or 'Artefakte im Lauf-Ordner.'}"
            )
            summary = dossier["summary"]
            (folder / "dossier.json").write_text(
                json.dumps(dossier, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            ledger_line = {
                "at": created,
                "queen_id": queen_id,
                "run_id": run_id,
                "soldier_id": soldier_id,
                "playbook_id": playbook_id,
                "event": "dossier",
                "message": summary,
            }
            (folder / "ledger.jsonl").write_text(
                json.dumps(ledger_line, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            self._conn.execute(
                """
                INSERT INTO runs (
                  run_id, queen_id, soldier_id, playbook_id, status, created_at, summary, dossier_json
                ) VALUES (?, ?, ?, ?, 'dossier', ?, ?, ?)
                """,
                (
                    run_id,
                    queen_id,
                    soldier_id,
                    playbook_id,
                    created,
                    summary,
                    json.dumps(dossier, ensure_ascii=False),
                ),
            )
            self._conn.execute(
                "INSERT INTO ledger (queen_id, run_id, at, message) VALUES (?, ?, ?, ?)",
                (queen_id, run_id, created, summary),
            )
            self._conn.execute(
                """
                UPDATE soldier_state
                SET mode = 'lauf', tut = 'ein Dossier', live_satz = ?
                WHERE queen_id = ? AND soldier_id = ?
                """,
                (
                    f"{soldier['name']} schreibt das Dossier und bleibt im Scope.",
                    queen_id,
                    soldier_id,
                ),
            )
            self._conn.commit()
            return dossier

    def classify_probe(self, name: str, declared: str | None, oversight: bool) -> dict:
        cleaned = name.strip()
        if not cleaned or len(cleaned) > 180:
            raise ColonyError(400, "Ich brauche einen Probenamen, höchstens 180 Zeichen.")
        with self._lock:
            if not self._hit(
                self._classify_at, self.settings.classify_limit, self.settings.classify_window_s
            ):
                raise ColonyError(429, "Zu viele Klassifikationen. Ich drossele die Gelbe Königin.")
            armed = self._armed("yellow")
        show = bool(oversight and armed)
        if oversight and not armed:
            result = classify(cleaned, declared, False)
            result["note"] = (
                "Oversight ist in der Kolonie nicht gesetzt. "
                "Ich zeige nur die Hülle und halte die tiefen Schritte zurück."
            )
            result["withheld"] = result["withheld"] or result["withheld_count"] > 0
            return result
        return classify(cleaned, declared, show)

    def brain(self) -> dict:
        with self._lock:
            queens = [self._queen_summary_locked(queen) for queen in QUEEN_IDS]
            for queen, summary in zip(QUEEN_IDS, queens, strict=True):
                summary["soldiers"] = [
                    self._public_soldier(queen, item) for item in SOLDIERS[queen]
                ]
        from api.real_queens import enrich_summary
        queens = [enrich_summary(summary) for summary in queens]
        strip = " · ".join(item["strip_teil"] for item in queens)
        return {
            "product": PRODUCT,
            "description": DESCRIPTION,
            "footer": FOOTER,
            "queens": queens,
            "strip": strip,
        }


def assert_runnable(playbook: dict) -> None:
    if playbook.get("destructive"):
        raise ColonyError(403, "Destruktive Playbooks sind aus.")
