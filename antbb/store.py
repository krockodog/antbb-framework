"""Persistenz-Schicht (SQLite) für Targets, Oversight, Findings und Reports.

Ein einziger Store, den sowohl CLI als auch Webserver nutzen. Keine
Logik-Duplizierung: alle Lese-/Schreibzugriffe laufen hier durch.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

DEFAULT_DB_PATH = os.environ.get(
    "ANTBB_DB",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "antbb.db"),
)


# Rollen fuer Web-Benutzer. member = Operator (Scope/Oversight/Scans), kein
# User-Management. viewer/guest_user = Gast (Deny-by-Default in hosted).
USER_ROLES = ("admin", "member", "member_plus", "viewer", "guest_user")



def _now() -> float:
    return time.time()


# Ein Lock pro Store-Instanz: sqlite3.Connection ist auch mit
# check_same_thread=False nicht thread-sicher. Ohne Serialisierung kommt es
# unter parallelen Requests zu "InterfaceError: bad parameter or other API misuse".
_RETRY_DELAY = 0.05


def _retryable(exc: BaseException) -> bool:
    if isinstance(exc, sqlite3.InterfaceError):
        return True
    if isinstance(exc, sqlite3.OperationalError):
        msg = str(exc).lower()
        return "locked" in msg or "busy" in msg
    return False


def _call_once(fn):
    try:
        return fn()
    except (sqlite3.InterfaceError, sqlite3.OperationalError) as exc:
        if not _retryable(exc):
            raise
        time.sleep(_RETRY_DELAY)
        return fn()


class _LockedCursor:
    """Cursor-Wrapper: fetch/execute bleiben unter dem Store-RLock."""

    def __init__(self, cursor, lock: threading.RLock):
        self._cursor = cursor
        self._lock = lock

    def execute(self, *args, **kwargs):
        with self._lock:
            _call_once(lambda: self._cursor.execute(*args, **kwargs))
        return self

    def executemany(self, *args, **kwargs):
        with self._lock:
            _call_once(lambda: self._cursor.executemany(*args, **kwargs))
        return self

    def executescript(self, *args, **kwargs):
        with self._lock:
            _call_once(lambda: self._cursor.executescript(*args, **kwargs))
        return self

    def fetchone(self):
        with self._lock:
            return self._cursor.fetchone()

    def fetchall(self):
        with self._lock:
            return self._cursor.fetchall()

    def fetchmany(self, size=None):
        with self._lock:
            if size is None:
                return self._cursor.fetchmany()
            return self._cursor.fetchmany(size)

    def close(self):
        with self._lock:
            return self._cursor.close()

    def __iter__(self):
        with self._lock:
            rows = list(self._cursor)
        return iter(rows)

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def description(self):
        return self._cursor.description

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class _LockedConnection:
    """Serialisiert alle Connection-Aufrufe; Cursor werden mitverpackt.

    Bestehende Aufrufer (auch store._conn direkt in governance/activity/brain_ops)
    bleiben unverändert. RLock ist reentrant, verschachtelte Store-Aufrufe
    in derselben Transaktion/Thread blockieren sich nicht.
    """

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock):
        self._raw = conn
        self._lock = lock

    def execute(self, *args, **kwargs):
        with self._lock:
            cur = _call_once(lambda: self._raw.execute(*args, **kwargs))
            return _LockedCursor(cur, self._lock)

    def executemany(self, *args, **kwargs):
        with self._lock:
            cur = _call_once(lambda: self._raw.executemany(*args, **kwargs))
            return _LockedCursor(cur, self._lock)

    def executescript(self, sql):
        with self._lock:
            cur = _call_once(lambda: self._raw.executescript(sql))
            return _LockedCursor(cur, self._lock)

    def commit(self):
        with self._lock:
            return _call_once(self._raw.commit)

    def rollback(self):
        with self._lock:
            return _call_once(self._raw.rollback)

    def close(self):
        with self._lock:
            return self._raw.close()

    def cursor(self, *args, **kwargs):
        with self._lock:
            return _LockedCursor(self._raw.cursor(*args, **kwargs), self._lock)

    def backup(self, target, *args, **kwargs):
        raw_target = getattr(target, "_raw", target)
        with self._lock:
            return self._raw.backup(raw_target, *args, **kwargs)

    def interrupt(self):
        # interrupt() darf den Lock nicht nehmen: sonst kann ein anderer
        # Thread eine hängende Operation nicht abbrechen.
        return self._raw.interrupt()

    def __enter__(self):
        self._lock.acquire()
        self._raw.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            return self._raw.__exit__(exc_type, exc, tb)
        finally:
            self._lock.release()

    def __getattr__(self, name):
        return getattr(self._raw, name)


SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    mode_policy TEXT NOT NULL DEFAULT 'auto',  -- defensive | auto | offensive
    created_at  REAL NOT NULL,
    archived_at REAL  -- NULL = aktiv; gesetzt = im Papierkorb (Soft-Delete)
);

CREATE TABLE IF NOT EXISTS scopes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  INTEGER NOT NULL,
    kind       TEXT NOT NULL,          -- domain | ip | path | url
    value      TEXT NOT NULL,
    allowed    INTEGER NOT NULL DEFAULT 1,  -- 1 = in-scope, 0 = out-of-scope
    created_at REAL NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS oversight (
    target_id   INTEGER PRIMARY KEY,
    confirmed   INTEGER NOT NULL DEFAULT 0,
    confirmed_by TEXT DEFAULT '',
    note        TEXT DEFAULT '',
    confirmed_at REAL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    run_id      TEXT NOT NULL,
    agent       TEXT NOT NULL,
    title       TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,          -- info|low|medium|high|critical
    asset       TEXT DEFAULT '',
    description TEXT DEFAULT '',
    evidence    TEXT DEFAULT '',        -- JSON
    dedup_key   TEXT NOT NULL,
    status      TEXT DEFAULT '',        -- Beweis-Stufe (VERIFIZIERT/BESTÄTIGT(PASSIV)/...)
    false_positive INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    title       TEXT NOT NULL,
    cvss_score  REAL,
    cvss_vector TEXT DEFAULT '',
    severity    TEXT DEFAULT '',
    chain       TEXT NOT NULL,          -- JSON mit 8-Schritt-Evidence-Kette
    created_at  REAL NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS capabilities (
    id         INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton: Königin-Gedächtnis
    registry   TEXT NOT NULL,          -- JSON der Capability-Registry
    built_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS report_addenda (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id   INTEGER NOT NULL,
    author      TEXT DEFAULT '',
    text        TEXT NOT NULL,
    created_at  REAL NOT NULL,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS report_revisions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id   INTEGER NOT NULL,
    revision    INTEGER NOT NULL,
    instruction TEXT DEFAULT '',
    body        TEXT NOT NULL,
    author      TEXT DEFAULT '',
    created_at  REAL NOT NULL,
    FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS soldier_overrides (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    soldier     TEXT NOT NULL,
    playbook    TEXT NOT NULL DEFAULT '',   -- '' = Soldat-weit
    key         TEXT NOT NULL,              -- enabled | intensity | flags | description | task:<name>
    value       TEXT NOT NULL DEFAULT '',
    updated_at  REAL NOT NULL,
    UNIQUE(soldier, playbook, key)
);

CREATE TABLE IF NOT EXISTS soldier_mems (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    soldier     TEXT NOT NULL,
    text        TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS wlan_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER,                    -- optional; Survey kann target-los sein
    point_label TEXT NOT NULL,              -- Mess-Punkt (z.B. "Wohnzimmer")
    bssid       TEXT NOT NULL,
    ssid        TEXT DEFAULT '',
    rssi        INTEGER,                     -- dBm (gemessen)
    channel     INTEGER,
    band        TEXT DEFAULT '',            -- 2.4 | 5 | 6
    is_own      INTEGER NOT NULL DEFAULT 0, -- eigene Fritzbox getaggt
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS wlan_engagements (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    target_id    INTEGER,                    -- optional Verknüpfung zu einem Target
    bssids       TEXT NOT NULL DEFAULT '[]', -- JSON-Liste autorisierter BSSIDs (Allowlist)
    ssids        TEXT NOT NULL DEFAULT '[]', -- JSON-Liste autorisierter SSIDs (Allowlist)
    client_mac   TEXT DEFAULT '',            -- optionaler, eng begrenzter Client
    location     TEXT DEFAULT '',
    start_ts     REAL NOT NULL,              -- Beginn des autorisierten Zeitfensters
    end_ts       REAL NOT NULL,              -- Ende des autorisierten Zeitfensters
    oversight    INTEGER NOT NULL DEFAULT 0, -- Oversight-Häkchen für diese Engagement
    revoked      INTEGER NOT NULL DEFAULT 0,
    created_at   REAL NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    run_id      TEXT PRIMARY KEY,           -- Replay/Checkpoint: Lauf-ID
    target_id   INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running', -- running|paused|done|error
    phases      TEXT DEFAULT '[]',          -- JSON der geplanten Phasen
    meta        TEXT DEFAULT '{}',          -- JSON (active/fuzz/offensive etc.)
    started_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    finished_at REAL,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_steps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    seq         INTEGER NOT NULL,           -- deterministische Reihenfolge
    phase       TEXT DEFAULT '',
    agent       TEXT DEFAULT '',
    kind        TEXT NOT NULL,              -- event|finding|phase|status
    payload     TEXT NOT NULL DEFAULT '{}', -- JSON (re-emittierbar)
    created_at  REAL NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wlan_credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    kind          TEXT NOT NULL,             -- handshake|pmkid|cracked|portal-cred
    bssid         TEXT DEFAULT '',
    ssid          TEXT DEFAULT '',
    label         TEXT DEFAULT '',           -- z.B. Benutzername (maskiert) / Capture-Datei
    masked        TEXT NOT NULL DEFAULT '',  -- maskierte Darstellung (NIE Klartext)
    digest        TEXT NOT NULL DEFAULT '',  -- gesalzener SHA-256 (NIE Klartext)
    char_count    INTEGER,                   -- Länge als Nachweis
    created_at    REAL NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES wlan_engagements(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,          -- z.B. 'remote_access_mode'
    value      TEXT NOT NULL DEFAULT '',  -- NIE Secrets; nur Präferenzen/Status
    updated_at REAL NOT NULL
);

-- ---- WLAN-Coverage-Heatmap (passive RSSI-Messpunkte mit x/y-Position) ------
-- Rein passive Signalstärke-Messung (RSSI) aus dem vorhandenen Scan, verortet
-- durch Klick auf einen (optionalen) Grundriss oder ein leeres Raster. Keine
-- Angriffe, keine Secrets. x/y sind NORMALISIERTE Koordinaten 0..1 relativ zur
-- Grundrissfläche, damit die Darstellung auflösungsunabhängig bleibt.
CREATE TABLE IF NOT EXISTS wlan_heatmap_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER,                    -- optional; Heatmap kann target-los sein
    ort         TEXT NOT NULL DEFAULT '',   -- optionaler Mess-Punkt-/Raum-Name
    x           REAL NOT NULL,              -- 0..1 relativ zur Fläche
    y           REAL NOT NULL,              -- 0..1 relativ zur Fläche
    bssid       TEXT NOT NULL,
    ssid        TEXT DEFAULT '',
    rssi        INTEGER,                     -- dBm (gemessen, echt)
    channel     INTEGER,
    band        TEXT DEFAULT '',            -- 2.4 | 5 | 6
    is_own      INTEGER NOT NULL DEFAULT 0, -- eigener AP getaggt
    created_at  REAL NOT NULL
);

-- Optionaler Grundriss-Upload pro Target (oder global, target_id NULL). Bild wird
-- als Data-URL (base64) gespeichert; KEINE Secrets, nur eine Zeichnung/Karte.
CREATE TABLE IF NOT EXISTS wlan_floorplans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER,                    -- NULL = global
    filename    TEXT DEFAULT '',
    mime        TEXT DEFAULT 'image/png',
    data_url    TEXT NOT NULL,              -- data:image/...;base64,....
    created_at  REAL NOT NULL
);

-- ---- Auth / Multi-User (optional, via ANTBB_AUTH=1) ----------------------
-- Passwoerter werden NUR als gesalzener PBKDF2-HMAC-Hash gespeichert, NIE im
-- Klartext. pw_hash/pw_salt sind Hex-Strings; kein Klartext, kein Log.
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    pw_hash    TEXT NOT NULL,             -- PBKDF2-HMAC-SHA256 (hex)
    pw_salt    TEXT NOT NULL,             -- zufaelliges Salz (hex)
    pw_iter    INTEGER NOT NULL DEFAULT 240000,
    role       TEXT NOT NULL DEFAULT 'viewer',  -- admin | member | member_plus | viewer | guest_user
    active      INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,          -- zufaelliges Token (nie geloggt)
    username   TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'viewer',
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

-- ---- Sicherheits-Alarme (nur Web-UI, nur admin sichtbar) -------------------
-- Kein E-Mail-/Push-Versand. Quittieren setzt acked_at, nichts wird geloescht.
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,             -- login_limited | admin_denied | owner_denied | invite_invalid | ...
    severity   TEXT NOT NULL DEFAULT 'warn',
    username   TEXT,                      -- NULL = nicht angemeldet
    ip         TEXT DEFAULT '',
    path       TEXT DEFAULT '',
    detail     TEXT DEFAULT '',
    created_at REAL NOT NULL,
    acked_at   REAL,
    acked_by   TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts(acked_at);

-- ---- Einladungen (Admin-Portal) -------------------------------------------
-- Einladungslink /invite/<token>. Die eingeladene Person waehlt ihr Passwort
-- selbst. Widerruf ist weich (revoked=1), nichts wird geloescht.
CREATE TABLE IF NOT EXISTS invites (
    token      TEXT PRIMARY KEY,          -- secrets.token_urlsafe (nie voll geloggt)
    ref        TEXT UNIQUE,               -- kurze, oeffentliche Kennung fuer Liste/Widerruf
    email      TEXT NOT NULL DEFAULT '',  -- optional, lowercased
    username   TEXT NOT NULL DEFAULT '',  -- optional vorbelegt (dann fest)
    role       TEXT NOT NULL DEFAULT 'member',
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    used_at    REAL,
    used_by    TEXT,
    revoked    INTEGER NOT NULL DEFAULT 0
);

-- ---- Opt-in: eigene Assets fuer ungefaehrliche TLS/Header-Checks ----------
-- Default-deny: ein Check laeuft NUR gegen Assets, die hier als EIGEN bestaetigt
-- sind (confirmed_owner=1). Kein aktiver/offensiver Payload.
CREATE TABLE IF NOT EXISTS owned_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    label           TEXT DEFAULT '',
    host            TEXT NOT NULL,         -- Hostname/Domain (ohne Schema)
    port            INTEGER NOT NULL DEFAULT 443,
    confirmed_owner INTEGER NOT NULL DEFAULT 0,  -- 1 = Besitz ausdruecklich bestaetigt
    confirmed_by    TEXT DEFAULT '',
    note            TEXT DEFAULT '',
    created_at      REAL NOT NULL,
    UNIQUE(host, port)
);

CREATE TABLE IF NOT EXISTS asset_check_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 443,
    kind        TEXT NOT NULL,             -- tls | headers
    ok          INTEGER NOT NULL DEFAULT 0,
    summary     TEXT DEFAULT '',
    result      TEXT NOT NULL DEFAULT '{}',-- JSON (keine Secrets)
    created_at  REAL NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES owned_assets(id) ON DELETE CASCADE
);

-- ---- Persistente Run-Historie (UI) ---------------------------------------
-- Jeder abgeschlossene/abgebrochene Lauf wird mit Metadaten festgehalten.
CREATE TABLE IF NOT EXISTS run_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT,
    target_id     INTEGER,
    target_name   TEXT DEFAULT '',
    mode          TEXT DEFAULT 'defensive', -- defensive | active | fuzz | offensive
    active        INTEGER NOT NULL DEFAULT 0,
    fuzz          INTEGER NOT NULL DEFAULT 0,
    offensive     INTEGER NOT NULL DEFAULT 0,
    status        TEXT DEFAULT 'done',      -- done | error
    finding_count INTEGER NOT NULL DEFAULT 0,
    severity      TEXT NOT NULL DEFAULT '{}',-- JSON Verteilung
    error         TEXT DEFAULT '',
    started_at    REAL,
    finished_at   REAL,
    duration      REAL,
    created_at    REAL NOT NULL
);

-- ---- Blue Queen: wiederholbare Jobs ------------------------------------
-- Jobs sind Definitionen (Art, Intervall, Params). Runs halten den Verlauf.
CREATE TABLE IF NOT EXISTS blue_jobs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL,          -- swscan | hardening | remediate | colony
    enabled       INTEGER NOT NULL DEFAULT 1,
    interval_sec  INTEGER NOT NULL DEFAULT 86400,
    target_id     INTEGER,
    params_json   TEXT NOT NULL DEFAULT '{}',
    last_run_at   REAL,
    next_run_at   REAL,
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS blue_job_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id        INTEGER NOT NULL,
    run_id        TEXT,
    status        TEXT DEFAULT 'done',   -- done | error | skipped
    finding_count INTEGER NOT NULL DEFAULT 0,
    closed_count  INTEGER NOT NULL DEFAULT 0,
    summary_json  TEXT NOT NULL DEFAULT '{}',
    error         TEXT DEFAULT '',
    started_at    REAL,
    finished_at   REAL,
    created_at    REAL NOT NULL,
    FOREIGN KEY(job_id) REFERENCES blue_jobs(id) ON DELETE CASCADE
);

-- ---- Blue Queen: permanenter Attack-Log (append-only) -------------------
CREATE TABLE IF NOT EXISTS attack_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type    TEXT NOT NULL,
    source        TEXT DEFAULT '',
    action        TEXT DEFAULT '',
    countermeasure TEXT DEFAULT '',
    outcome       TEXT DEFAULT '',
    before_json   TEXT NOT NULL DEFAULT '{}',
    after_json    TEXT NOT NULL DEFAULT '{}',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    run_id        TEXT DEFAULT '',
    target_id     INTEGER,
    severity      TEXT DEFAULT 'info',
    ts            REAL NOT NULL,
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attack_events_ts ON attack_events(ts);
CREATE INDEX IF NOT EXISTS idx_attack_events_run ON attack_events(run_id);

"""


class Store:
    """Zentraler Datenspeicher. Thread-/prozessübergreifend via SQLite-Datei."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.RLock()
        raw = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA foreign_keys = ON;")
        raw.execute("PRAGMA journal_mode = WAL;")
        raw.execute("PRAGMA busy_timeout = 30000;")
        raw.execute("PRAGMA synchronous = NORMAL;")
        self._conn = _LockedConnection(raw, self._lock)
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _migrate(self) -> None:
        """Idempotente Schema-Erweiterungen für bestehende DBs."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(targets)").fetchall()}
        if "mode_policy" not in cols:
            self._conn.execute(
                "ALTER TABLE targets ADD COLUMN mode_policy TEXT NOT NULL DEFAULT 'auto'"
            )
        if "archived_at" not in cols:
            # Soft-Delete / Papierkorb: NULL = aktiv, Zeitstempel = archiviert.
            # Keine Daten werden entfernt, nur ausgeblendet.
            self._conn.execute(
                "ALTER TABLE targets ADD COLUMN archived_at REAL"
            )
        fcols = {r[1] for r in self._conn.execute("PRAGMA table_info(findings)").fetchall()}
        if "status" not in fcols:
            self._conn.execute(
                "ALTER TABLE findings ADD COLUMN status TEXT DEFAULT ''"
            )
        if "false_positive" not in fcols:
            self._conn.execute(
                "ALTER TABLE findings ADD COLUMN false_positive INTEGER NOT NULL DEFAULT 0"
            )
        hcols = {r[1] for r in self._conn.execute("PRAGMA table_info(run_history)").fetchall()}
        if "started_by" not in hcols:
            self._conn.execute(
                "ALTER TABLE run_history ADD COLUMN started_by TEXT NOT NULL DEFAULT ''"
            )
        # Pro-User-Trennung (additiv, nullable). Alt-Eintraege bleiben NULL =
        # "ohne Zuordnung" und sind nur fuer admin sichtbar. Kein Backfill.
        if "owner_user" not in hcols:
            self._conn.execute("ALTER TABLE run_history ADD COLUMN owner_user TEXT")
        if "owner_user" not in cols:
            self._conn.execute("ALTER TABLE targets ADD COLUMN owner_user TEXT")
        # 2FA (TOTP) + Kick/Sperre – additiv, nullable.
        ucols = {r[1] for r in self._conn.execute("PRAGMA table_info(users)").fetchall()}
        for col, ddl in (
            ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
            ("totp_secret_enc", "TEXT"),
            ("totp_pending_enc", "TEXT"),
            ("totp_last_step", "INTEGER"),
            ("recovery_hashes", "TEXT"),
            ("disabled_at", "REAL"),
            ("disabled_by", "TEXT"),
        ):
            if col not in ucols:
                self._conn.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")

    # ---------------- Targets ----------------
    def add_target(self, name: str, description: str = "",
                   mode_policy: str = "auto") -> int:
        pol = mode_policy if mode_policy in ("defensive", "auto", "offensive") else "auto"
        cur = self._conn.execute(
            "INSERT INTO targets (name, description, mode_policy, created_at) "
            "VALUES (?,?,?,?)",
            (name, description, pol, _now()),
        )
        tid = cur.lastrowid
        self._conn.execute(
            "INSERT OR IGNORE INTO oversight (target_id, confirmed) VALUES (?, 0)",
            (tid,),
        )
        self._conn.commit()
        return tid

    def get_target(self, name_or_id: Any) -> Optional[sqlite3.Row]:
        if isinstance(name_or_id, int) or str(name_or_id).isdigit():
            row = self._conn.execute(
                "SELECT * FROM targets WHERE id=?", (int(name_or_id),)
            ).fetchone()
            if row:
                return row
        return self._conn.execute(
            "SELECT * FROM targets WHERE name=?", (str(name_or_id),)
        ).fetchone()

    def list_targets_owned(self, owner: str) -> list[sqlite3.Row]:
        """Aktive Targets eines Benutzers (Pro-User-Trennung fuer member/member_plus)."""
        return self._conn.execute(
            "SELECT * FROM targets WHERE archived_at IS NULL AND owner_user=? "
            "ORDER BY created_at DESC", (owner,)).fetchall()

    def list_targets(self, include_archived: bool = False) -> list[sqlite3.Row]:
        """Aktive Targets (Default). Archivierte (Papierkorb) sind ausgeblendet,
        bleiben aber vollständig in der DB. include_archived=True listet alle."""
        if include_archived:
            return self._conn.execute(
                "SELECT * FROM targets ORDER BY created_at DESC"
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM targets WHERE archived_at IS NULL ORDER BY created_at DESC"
        ).fetchall()

    def list_archived_targets(self) -> list[sqlite3.Row]:
        """Papierkorb: nur archivierte Targets, zuletzt archiviert zuerst."""
        return self._conn.execute(
            "SELECT * FROM targets WHERE archived_at IS NOT NULL "
            "ORDER BY archived_at DESC"
        ).fetchall()

    def is_archived(self, target_id: int) -> bool:
        row = self._conn.execute(
            "SELECT archived_at FROM targets WHERE id=?", (target_id,),
        ).fetchone()
        return bool(row and row["archived_at"] is not None)

    def archive_target(self, target_id: int) -> None:
        """Soft-Delete: verschiebt ein Target in den Papierkorb. Es verschwindet
        aus der aktiven Liste und wird von aktiven Scans ausgeschlossen, aber
        ALLE Daten (Scopes, Findings, Scan-Historie, WLAN, Reports) bleiben
        unangetastet erhalten. Das Königin-Gedächtnis (Registry/Neural-Brain,
        Skills/Playbooks, soldier_mems/overrides) wird NICHT berührt."""
        self._conn.execute(
            "UPDATE targets SET archived_at=? WHERE id=? AND archived_at IS NULL",
            (_now(), target_id),
        )
        self._conn.commit()

    def restore_target(self, target_id: int) -> None:
        """Hebt die Archivierung auf (wiederherstellen aus dem Papierkorb)."""
        self._conn.execute(
            "UPDATE targets SET archived_at=NULL WHERE id=?", (target_id,),
        )
        self._conn.commit()

    def delete_target(self, target_id: int) -> None:
        """Harte, endgültige Löschung (Purge) EINES Targets samt seiner
        target-skopierten Zeilen (Scopes/Findings/Reports/Scan-Historie via
        ON DELETE CASCADE). Das aggregierte Königin-Wissen bleibt erhalten:
        capabilities-Registry, soldier_mems und soldier_overrides sind NICHT
        an ein Target gebunden und werden von dieser Löschung nicht berührt.
        Wird aktuell NICHT über die GUI angeboten (Default: nur Papierkorb)."""
        self._conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
        self._conn.commit()

    def set_mode_policy(self, target_id: int, policy: str) -> None:
        pol = policy if policy in ("defensive", "auto", "offensive") else "auto"
        self._conn.execute(
            "UPDATE targets SET mode_policy=? WHERE id=?", (pol, target_id),
        )
        self._conn.commit()

    def get_mode_policy(self, target_id: int) -> str:
        row = self._conn.execute(
            "SELECT mode_policy FROM targets WHERE id=?", (target_id,),
        ).fetchone()
        if not row:
            return "auto"
        val = row["mode_policy"] if "mode_policy" in row.keys() else "auto"
        return val if val in ("defensive", "auto", "offensive") else "auto"

    # ---------------- Scopes ----------------
    def add_scope(self, target_id: int, kind: str, value: str, allowed: bool = True) -> int:
        cur = self._conn.execute(
            "INSERT INTO scopes (target_id, kind, value, allowed, created_at) "
            "VALUES (?,?,?,?,?)",
            (target_id, kind, value, 1 if allowed else 0, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_scopes(self, target_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM scopes WHERE target_id=? ORDER BY id", (target_id,)
        ).fetchall()

    def delete_scope(self, scope_id: int) -> None:
        self._conn.execute("DELETE FROM scopes WHERE id=?", (scope_id,))
        self._conn.commit()

    # ---------------- Oversight ----------------
    def set_oversight(self, target_id: int, confirmed: bool,
                      confirmed_by: str = "", note: str = "") -> None:
        self._conn.execute(
            "INSERT INTO oversight (target_id, confirmed, confirmed_by, note, confirmed_at) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(target_id) DO UPDATE SET confirmed=excluded.confirmed, "
            "confirmed_by=excluded.confirmed_by, note=excluded.note, "
            "confirmed_at=excluded.confirmed_at",
            (target_id, 1 if confirmed else 0, confirmed_by, note,
             _now() if confirmed else None),
        )
        self._conn.commit()

    def get_oversight(self, target_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM oversight WHERE target_id=?", (target_id,)
        ).fetchone()

    def is_confirmed(self, target_id: int) -> bool:
        row = self.get_oversight(target_id)
        return bool(row and row["confirmed"])

    # ---------------- Findings ----------------
    def add_finding(self, target_id: int, run_id: str, agent: str, title: str,
                    category: str, severity: str, asset: str = "",
                    description: str = "", evidence: Optional[dict] = None,
                    dedup_key: str = "", status: str = "",
                    false_positive: bool = False) -> Optional[int]:
        dedup_key = dedup_key or f"{category}:{title}:{asset}"
        # Dedup: gleiche dedup_key innerhalb desselben Targets wird verworfen
        existing = self._conn.execute(
            "SELECT id FROM findings WHERE target_id=? AND dedup_key=?",
            (target_id, dedup_key),
        ).fetchone()
        if existing:
            return None
        cur = self._conn.execute(
            "INSERT INTO findings (target_id, run_id, agent, title, category, "
            "severity, asset, description, evidence, dedup_key, status, "
            "false_positive, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (target_id, run_id, agent, title, category, severity, asset,
             description, json.dumps(evidence or {}), dedup_key, status,
             1 if false_positive else 0, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    # ---------------- Capability-Registry (Königin-Gedächtnis) ----------------
    def replace_capabilities(self, registry: dict) -> None:
        """Ersetzt die persistierte Capability-Registry (Singleton, id=1)."""
        self._conn.execute("DELETE FROM capabilities WHERE id=1")
        self._conn.execute(
            "INSERT INTO capabilities (id, registry, built_at) VALUES (1, ?, ?)",
            (json.dumps(registry, ensure_ascii=False),
             float(registry.get("built_at") or _now())),
        )
        self._conn.commit()

    def get_capabilities(self) -> dict:
        """Liest die persistierte Capability-Registry (oder {} wenn leer)."""
        row = self._conn.execute(
            "SELECT registry FROM capabilities WHERE id=1"
        ).fetchone()
        if not row:
            return {}
        try:
            return json.loads(row["registry"])
        except Exception:
            return {}

    # ---------------- Settings (kleines KV, NIE Secrets) ----------------
    def get_setting(self, key: str, default: str = "") -> str:
        """Liest eine Einstellung. Nur Präferenzen/Status – niemals Secrets."""
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        """Setzt eine Einstellung (Upsert). Es werden NIE Secrets/Tokens hier
        abgelegt – nur unkritische Präferenzen (z.B. Fernzugriff-Modus)."""
        self._conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
            "updated_at=excluded.updated_at",
            (key, str(value), _now()),
        )
        self._conn.commit()

    # ---------------- WLAN-Zustand (letzter Scan, letzte Schätzung) ----------------
    def set_wlan_state(self, key: str, value: str) -> None:
        """Persistiert WLAN-Status (z.B. letzter Scan / Grundriss-Schätzung).
        Nur Messdaten/Darstellung – niemals Secrets."""
        self.set_setting(f"wlan.{key}", value)

    def get_wlan_state(self, key: str) -> Optional[str]:
        """Liest WLAN-Status; None wenn nicht vorhanden."""
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key=?", (f"wlan.{key}",)
        ).fetchone()
        return row["value"] if row else None

    # ---------------- Auth / Multi-User (optional) ----------------
    def count_users(self) -> int:
        r = self._conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        return int(r["c"]) if r else 0

    def get_user(self, username: str):
        return self._conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)).fetchone()

    def list_users(self):
        return self._conn.execute(
            "SELECT id, username, role, active, created_at, "
            "COALESCE(totp_enabled,0) AS totp_enabled, disabled_at, disabled_by "
            "FROM users ORDER BY created_at").fetchall()

    def create_user(self, username: str, pw_hash: str, pw_salt: str,
                    role: str = "viewer", pw_iter: int = 240000) -> int:
        role = role if role in USER_ROLES else "viewer"
        cur = self._conn.execute(
            "INSERT INTO users (username, pw_hash, pw_salt, pw_iter, role, "
            "active, created_at) VALUES (?,?,?,?,?,1,?)",
            (username, pw_hash, pw_salt, int(pw_iter), role, _now()))
        self._conn.commit()
        return cur.lastrowid

    def update_user_password(self, username: str, pw_hash: str, pw_salt: str,
                             pw_iter: int = 240000) -> None:
        self._conn.execute(
            "UPDATE users SET pw_hash=?, pw_salt=?, pw_iter=? WHERE username=?",
            (pw_hash, pw_salt, int(pw_iter), username))
        self._conn.commit()

    def set_user_role(self, username: str, role: str) -> None:
        role = role if role in USER_ROLES else "viewer"
        self._conn.execute("UPDATE users SET role=? WHERE username=?",
                           (role, username))
        # Laufende Sessions sofort auf die neue Rolle ziehen (kein Re-Login noetig,
        # keine veraltete Admin-Session nach einer Herabstufung).
        self._conn.execute("UPDATE sessions SET role=? WHERE username=?",
                           (role, username))
        self._conn.commit()

    def set_user_active(self, username: str, active: bool) -> None:
        """Weiches Deaktivieren. Inaktive Benutzer verlieren alle Sessions."""
        self._conn.execute("UPDATE users SET active=? WHERE username=?",
                           (1 if active else 0, username))
        if not active:
            self._conn.execute("DELETE FROM sessions WHERE username=?", (username,))
        self._conn.commit()

    def set_user_disabled(self, username: str, disabled: bool, by: str = "") -> None:
        """Kick & Sperre: active=0 + disabled_at, alle Sessions sofort weg.
        Entsperren setzt active=1. Nichts wird geloescht."""
        if disabled:
            self._conn.execute(
                "UPDATE users SET active=0, disabled_at=?, disabled_by=? WHERE username=?",
                (_now(), by, username))
            self._conn.execute("DELETE FROM sessions WHERE username=?", (username,))
            self._conn.execute(
                "UPDATE invites SET revoked=1 WHERE created_by=? AND used_at IS NULL",
                (username,))
        else:
            self._conn.execute(
                "UPDATE users SET active=1, disabled_at=NULL, disabled_by=NULL WHERE username=?",
                (username,))
        self._conn.commit()

    # ---- 2FA (Secret nur verschluesselt) ----
    def set_totp_pending(self, username: str, enc: Optional[str]) -> None:
        self._conn.execute("UPDATE users SET totp_pending_enc=? WHERE username=?",
                           (enc, username))
        self._conn.commit()

    def enable_totp(self, username: str, enc: str, step: int, recovery_json: str) -> None:
        self._conn.execute(
            "UPDATE users SET totp_enabled=1, totp_secret_enc=?, totp_pending_enc=NULL, "
            "totp_last_step=?, recovery_hashes=? WHERE username=?",
            (enc, int(step), recovery_json, username))
        self._conn.commit()

    def disable_totp(self, username: str) -> None:
        self._conn.execute(
            "UPDATE users SET totp_enabled=0, totp_secret_enc=NULL, totp_pending_enc=NULL, "
            "totp_last_step=NULL, recovery_hashes=NULL WHERE username=?", (username,))
        self._conn.commit()

    def set_totp_last_step(self, username: str, step: int) -> bool:
        """Atomar, Replay-Schutz: nur wenn step groesser als der gespeicherte."""
        cur = self._conn.execute(
            "UPDATE users SET totp_last_step=? WHERE username=? AND "
            "(totp_last_step IS NULL OR totp_last_step < ?)",
            (int(step), username, int(step)))
        self._conn.commit()
        return bool(cur.rowcount)

    def set_recovery_hashes(self, username: str, recovery_json: str) -> None:
        self._conn.execute("UPDATE users SET recovery_hashes=? WHERE username=?",
                           (recovery_json, username))
        self._conn.commit()

    def count_active_admins(self) -> int:
        r = self._conn.execute(
            "SELECT COUNT(*) AS c FROM users WHERE role='admin' AND active=1"
        ).fetchone()
        return int(r["c"]) if r else 0

    def delete_user(self, username: str) -> None:
        self._conn.execute("DELETE FROM users WHERE username=?", (username,))
        self._conn.commit()

    # ---- Einladungen (Token nie voll geloggt) ----
    def create_invite(self, token: str, ref: str, role: str, created_by: str,
                      email: str = "", username: str = "",
                      ttl_seconds: float = 86400 * 7) -> None:
        role = role if role in USER_ROLES else "member"
        now = _now()
        self._conn.execute(
            "INSERT INTO invites (token, ref, email, username, role, created_by, "
            "created_at, expires_at, revoked) VALUES (?,?,?,?,?,?,?,?,0)",
            (token, ref, (email or "").strip().lower(), (username or "").strip(),
             role, created_by, now, now + float(ttl_seconds)))
        self._conn.commit()

    def get_invite(self, token: str):
        if not token:
            return None
        return self._conn.execute(
            "SELECT * FROM invites WHERE token=?", (token,)).fetchone()

    def get_invite_by_ref(self, ref: str):
        if not ref:
            return None
        return self._conn.execute(
            "SELECT * FROM invites WHERE ref=?", (ref,)).fetchone()

    def list_invites(self, pending_only: bool = False):
        sql = "SELECT * FROM invites"
        args: tuple = ()
        if pending_only:
            sql += " WHERE revoked=0 AND used_at IS NULL AND expires_at >= ?"
            args = (_now(),)
        return self._conn.execute(sql + " ORDER BY created_at DESC", args).fetchall()

    def revoke_invite(self, token: str) -> bool:
        cur = self._conn.execute(
            "UPDATE invites SET revoked=1 WHERE token=? AND used_at IS NULL",
            (token,))
        self._conn.commit()
        return bool(cur.rowcount)

    def claim_invite(self, token: str, used_by: str) -> bool:
        """Atomar: nur ein offenes, gueltiges Invite kann eingeloest werden."""
        cur = self._conn.execute(
            "UPDATE invites SET used_at=?, used_by=? WHERE token=? AND revoked=0 "
            "AND used_at IS NULL AND expires_at >= ?",
            (_now(), used_by, token, _now()))
        self._conn.commit()
        return bool(cur.rowcount)

    def release_invite(self, token: str) -> None:
        """Claim zuruecknehmen, wenn das Anlegen des Benutzers scheiterte."""
        self._conn.execute(
            "UPDATE invites SET used_at=NULL, used_by=NULL WHERE token=?", (token,))
        self._conn.commit()

    def mark_invite_used(self, token: str, used_by: str) -> bool:
        return self.claim_invite(token, used_by)

    # ---- Sessions (Token nie geloggt) ----
    def create_session(self, token: str, username: str, role: str,
                       ttl_seconds: float = 86400 * 7) -> None:
        now = _now()
        self._conn.execute(
            "INSERT OR REPLACE INTO sessions (token, username, role, created_at, "
            "expires_at) VALUES (?,?,?,?,?)",
            (token, username, role, now, now + ttl_seconds))
        self._conn.commit()

    def get_session(self, token: str):
        if not token:
            return None
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
        if not row:
            return None
        if row["expires_at"] < _now():
            self.delete_session(token)
            return None
        return row

    def delete_session(self, token: str) -> None:
        self._conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        self._conn.commit()

    def delete_user_sessions(self, username: str, keep_token: str = "") -> int:
        """Alle Sessions eines Benutzers loeschen, optional eine behalten."""
        cur = self._conn.execute(
            "DELETE FROM sessions WHERE username=? AND token<>?",
            (username, keep_token or ""))
        self._conn.commit()
        return cur.rowcount or 0

    def purge_expired_sessions(self) -> int:
        cur = self._conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?", (_now(),))
        self._conn.commit()
        return cur.rowcount or 0

    # ---------------- Opt-in eigene Assets (TLS/Header-Checks) ----------------
    def add_owned_asset(self, host: str, port: int = 443, label: str = "",
                        confirmed_owner: bool = False, confirmed_by: str = "",
                        note: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO owned_assets (label, host, port, confirmed_owner, "
            "confirmed_by, note, created_at) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(host, port) DO UPDATE SET label=excluded.label, "
            "confirmed_owner=excluded.confirmed_owner, "
            "confirmed_by=excluded.confirmed_by, note=excluded.note",
            (label, host, int(port), 1 if confirmed_owner else 0,
             confirmed_by, note, _now()))
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM owned_assets WHERE host=? AND port=?",
            (host, int(port))).fetchone()
        return int(row["id"]) if row else int(cur.lastrowid)

    def get_owned_asset(self, asset_id: int):
        return self._conn.execute(
            "SELECT * FROM owned_assets WHERE id=?", (int(asset_id),)).fetchone()

    def list_owned_assets(self):
        return self._conn.execute(
            "SELECT * FROM owned_assets ORDER BY created_at DESC").fetchall()

    def set_owned_asset_confirmed(self, asset_id: int, confirmed: bool,
                                  confirmed_by: str = "") -> None:
        self._conn.execute(
            "UPDATE owned_assets SET confirmed_owner=?, confirmed_by=? WHERE id=?",
            (1 if confirmed else 0, confirmed_by, int(asset_id)))
        self._conn.commit()

    def delete_owned_asset(self, asset_id: int) -> None:
        self._conn.execute("DELETE FROM owned_assets WHERE id=?", (int(asset_id),))
        self._conn.commit()

    def add_asset_check_run(self, asset_id: int, host: str, port: int, kind: str,
                            ok: bool, summary: str, result: dict) -> int:
        cur = self._conn.execute(
            "INSERT INTO asset_check_runs (asset_id, host, port, kind, ok, "
            "summary, result, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (int(asset_id), host, int(port), kind, 1 if ok else 0, summary,
             json.dumps(result or {}), _now()))
        self._conn.commit()
        return cur.lastrowid

    def list_asset_check_runs(self, asset_id: Optional[int] = None, limit: int = 50):
        if asset_id is not None:
            return self._conn.execute(
                "SELECT * FROM asset_check_runs WHERE asset_id=? "
                "ORDER BY created_at DESC LIMIT ?",
                (int(asset_id), int(limit))).fetchall()
        return self._conn.execute(
            "SELECT * FROM asset_check_runs ORDER BY created_at DESC LIMIT ?",
            (int(limit),)).fetchall()

    # ---------------- Run-Historie (UI) ----------------
    def add_run_history(self, run_id: Optional[str], target_id: Optional[int],
                        target_name: str = "", mode: str = "defensive",
                        active: bool = False, fuzz: bool = False,
                        offensive: bool = False, status: str = "done",
                        finding_count: int = 0, severity: Optional[dict] = None,
                        error: str = "", started_at: Optional[float] = None,
                        finished_at: Optional[float] = None,
                        duration: Optional[float] = None,
                        started_by: str = "",
                        owner_user: Optional[str] = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO run_history (run_id, target_id, target_name, mode, "
            "active, fuzz, offensive, status, finding_count, severity, error, "
            "started_at, finished_at, duration, created_at, started_by, owner_user) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, target_id, target_name, mode, 1 if active else 0,
             1 if fuzz else 0, 1 if offensive else 0, status, int(finding_count),
             json.dumps(severity or {}), error, started_at, finished_at,
             duration, _now(), started_by or "", (owner_user or None)))
        self._conn.commit()
        return cur.lastrowid

    UNOWNED = object()  # Marker: nur Eintraege ohne Owner

    def list_run_history(self, target_id: Optional[int] = None, limit: int = 200,
                         owner: Any = None):
        """owner=None: alle (admin). owner="name": nur dessen Laeufe.
        owner=Store.UNOWNED: nur Alt-Eintraege ohne Zuordnung."""
        where, args = [], []
        if target_id is not None:
            where.append("target_id=?")
            args.append(int(target_id))
        if owner is Store.UNOWNED:
            where.append("(owner_user IS NULL OR owner_user='')")
        elif owner is not None:
            where.append("owner_user=?")
            args.append(str(owner))
        sql = "SELECT * FROM run_history"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(int(limit))
        return self._conn.execute(sql, tuple(args)).fetchall()

    def run_history_owners(self) -> list:
        rows = self._conn.execute(
            "SELECT COALESCE(NULLIF(owner_user,''), '') AS o, COUNT(*) AS n "
            "FROM run_history GROUP BY o ORDER BY o").fetchall()
        return [(r["o"], int(r["n"])) for r in rows]

    def set_target_owner(self, target_id: int, owner_user: Optional[str]) -> None:
        self._conn.execute("UPDATE targets SET owner_user=? WHERE id=?",
                           (owner_user or None, int(target_id)))
        self._conn.commit()

    def target_owner(self, target_id: int) -> Optional[str]:
        r = self._conn.execute("SELECT owner_user FROM targets WHERE id=?",
                               (int(target_id),)).fetchone()
        return (r["owner_user"] or None) if r else None

    def report_target_id(self, report_id: int) -> Optional[int]:
        try:
            r = self._conn.execute("SELECT target_id FROM reports WHERE id=?",
                                   (int(report_id),)).fetchone()
        except Exception:
            return None
        return int(r["target_id"]) if r and r["target_id"] is not None else None

    # ---------------- Sicherheits-Alarme (nur Web-UI) ----------------
    def add_alert(self, kind: str, *, username: Optional[str] = None, ip: str = "",
                  path: str = "", detail: str = "", severity: str = "warn",
                  dedupe_seconds: float = 300) -> Optional[int]:
        """Legt einen Alarm an. Gleicher offener Alarm (kind/user/ip/path) im
        Fenster wird nicht doppelt angelegt (kein Alarm-Flooding)."""
        since = _now() - float(dedupe_seconds)
        dup = self._conn.execute(
            "SELECT id FROM alerts WHERE acked_at IS NULL AND kind=? "
            "AND COALESCE(username,'')=? AND ip=? AND path=? AND created_at>=?",
            (kind, username or "", ip or "", (path or "")[:200], since)).fetchone()
        if dup:
            return None
        cur = self._conn.execute(
            "INSERT INTO alerts (kind, severity, username, ip, path, detail, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (kind, severity, username or None, ip or "", (path or "")[:200],
             (detail or "")[:300], _now()))
        self._conn.commit()
        return cur.lastrowid

    def alert_counts_since(self, kinds, since: float) -> dict:
        """{kind: anzahl} der Alarme dieser Arten seit ``since`` (quittiert oder nicht)."""
        kinds = list(kinds or [])
        if not kinds:
            return {}
        marks = ",".join("?" for _ in kinds)
        rows = self._conn.execute(
            f"SELECT kind, COUNT(*) AS n FROM alerts WHERE created_at>? AND kind IN ({marks}) "
            "GROUP BY kind", (float(since), *kinds)).fetchall()
        return {r["kind"]: int(r["n"]) for r in rows}

    def count_open_alerts(self) -> int:
        r = self._conn.execute(
            "SELECT COUNT(*) AS c FROM alerts WHERE acked_at IS NULL").fetchone()
        return int(r["c"]) if r else 0

    def list_alerts(self, open_only: bool = False, limit: int = 200):
        sql = "SELECT * FROM alerts"
        if open_only:
            sql += " WHERE acked_at IS NULL"
        return self._conn.execute(sql + " ORDER BY created_at DESC LIMIT ?",
                                  (int(limit),)).fetchall()

    def open_alert_users(self) -> dict:
        """{username|'' : anzahl} offener Alarme. '' = nicht angemeldet / IP."""
        rows = self._conn.execute(
            "SELECT COALESCE(username,'') AS u, COUNT(*) AS n FROM alerts "
            "WHERE acked_at IS NULL GROUP BY u").fetchall()
        return {r["u"]: int(r["n"]) for r in rows}

    def ack_alerts(self, acked_by: str, alert_id: Optional[int] = None) -> int:
        if alert_id is None:
            cur = self._conn.execute(
                "UPDATE alerts SET acked_at=?, acked_by=? WHERE acked_at IS NULL",
                (_now(), acked_by))
        else:
            cur = self._conn.execute(
                "UPDATE alerts SET acked_at=?, acked_by=? WHERE id=? AND acked_at IS NULL",
                (_now(), acked_by, int(alert_id)))
        self._conn.commit()
        return cur.rowcount or 0

    # ---------------- Report-Nachträge (Addenda) ----------------
    def add_addendum(self, report_id: int, text: str, author: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO report_addenda (report_id, author, text, created_at) "
            "VALUES (?,?,?,?)", (report_id, author, text, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_addenda(self, report_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM report_addenda WHERE report_id=? ORDER BY created_at",
            (report_id,),
        ).fetchall()

    # ---------------- Report-Revisionen (Neu-Anweisung / Historie) ----------------
    def add_revision(self, report_id: int, body: str, instruction: str = "",
                     author: str = "") -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(revision),0) AS m FROM report_revisions WHERE report_id=?",
            (report_id,),
        ).fetchone()
        nextrev = int(row["m"]) + 1 if row else 1
        cur = self._conn.execute(
            "INSERT INTO report_revisions (report_id, revision, instruction, body, "
            "author, created_at) VALUES (?,?,?,?,?,?)",
            (report_id, nextrev, instruction, body, author, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_revisions(self, report_id: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM report_revisions WHERE report_id=? ORDER BY revision",
            (report_id,),
        ).fetchall()

    def get_revision(self, revision_id: int) -> "Optional[sqlite3.Row]":
        return self._conn.execute(
            "SELECT * FROM report_revisions WHERE id=?", (revision_id,),
        ).fetchone()


    # ---------------- Soldaten-Overrides (editierbare Playbook-Parameter) ----------------
    def set_soldier_override(self, soldier: str, playbook: str, key: str,
                             value: str) -> int:
        self._conn.execute(
            "INSERT INTO soldier_overrides (soldier, playbook, key, value, updated_at) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(soldier, playbook, key) DO UPDATE SET value=excluded.value, "
            "updated_at=excluded.updated_at",
            (soldier, playbook or "", key, str(value), _now()),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM soldier_overrides WHERE soldier=? AND playbook=? AND key=?",
            (soldier, playbook or "", key)).fetchone()
        return int(row["id"]) if row else -1

    def list_soldier_overrides(self, soldier: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM soldier_overrides WHERE soldier=? ORDER BY playbook, key",
            (soldier,)).fetchall()

    def delete_soldier_override(self, soldier: str, playbook: str, key: str) -> None:
        self._conn.execute(
            "DELETE FROM soldier_overrides WHERE soldier=? AND playbook=? AND key=?",
            (soldier, playbook or "", key))
        self._conn.commit()

    # ---------------- Soldaten-Mems (Notizen/Gedächtnis je Soldat) ----------------
    def add_soldier_mem(self, soldier: str, text: str) -> int:
        cur = self._conn.execute(
            "INSERT INTO soldier_mems (soldier, text, created_at) VALUES (?,?,?)",
            (soldier, text, _now()))
        self._conn.commit()
        return cur.lastrowid

    def list_soldier_mems(self, soldier: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM soldier_mems WHERE soldier=? ORDER BY created_at DESC",
            (soldier,)).fetchall()

    def delete_soldier_mem(self, mem_id: int) -> None:
        self._conn.execute("DELETE FROM soldier_mems WHERE id=?", (mem_id,))
        self._conn.commit()

    def all_soldier_overrides(self) -> dict:
        """Alle Overrides gruppiert nach Soldat (für den Lauf)."""
        out: dict = {}
        for r in self._conn.execute("SELECT * FROM soldier_overrides").fetchall():
            out.setdefault(r["soldier"], []).append(
                {"playbook": r["playbook"], "key": r["key"], "value": r["value"]})
        return out

    def all_soldier_mems(self) -> dict:
        out: dict = {}
        for r in self._conn.execute(
                "SELECT * FROM soldier_mems ORDER BY created_at").fetchall():
            out.setdefault(r["soldier"], []).append(r["text"])
        return out

    def list_findings(self, target_id: Optional[int] = None,
                      run_id: Optional[str] = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM findings"
        conds, args = [], []
        if target_id is not None:
            conds.append("target_id=?")
            args.append(target_id)
        if run_id is not None:
            conds.append("run_id=?")
            args.append(run_id)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY created_at DESC"
        return self._conn.execute(q, args).fetchall()


    # ---------------- WLAN-Survey (passive Coverage-Messpunkte) ----------------
    def add_wlan_sample(self, point_label: str, bssid: str, rssi: Optional[int] = None,
                        ssid: str = "", channel: Optional[int] = None,
                        band: str = "", is_own: bool = False,
                        target_id: Optional[int] = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO wlan_samples (target_id, point_label, bssid, ssid, rssi, "
            "channel, band, is_own, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (target_id, point_label, (bssid or "").lower(), ssid, rssi, channel,
             band, 1 if is_own else 0, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_wlan_samples(self, target_id: Optional[int] = None) -> list[sqlite3.Row]:
        if target_id is None:
            return self._conn.execute(
                "SELECT * FROM wlan_samples ORDER BY created_at").fetchall()
        return self._conn.execute(
            "SELECT * FROM wlan_samples WHERE target_id=? OR target_id IS NULL "
            "ORDER BY created_at", (target_id,)).fetchall()

    def delete_wlan_point(self, point_label: str,
                          target_id: Optional[int] = None) -> None:
        if target_id is None:
            self._conn.execute(
                "DELETE FROM wlan_samples WHERE point_label=?", (point_label,))
        else:
            self._conn.execute(
                "DELETE FROM wlan_samples WHERE point_label=? AND "
                "(target_id=? OR target_id IS NULL)", (point_label, target_id))
        self._conn.commit()

    # ---------------- WLAN-Coverage-Heatmap (verortete passive RSSI-Messpunkte) ----------------
    def add_wlan_heatmap_sample(self, x: float, y: float, bssid: str,
                                rssi: Optional[int] = None, ssid: str = "",
                                channel: Optional[int] = None, band: str = "",
                                is_own: bool = False, ort: str = "",
                                target_id: Optional[int] = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO wlan_heatmap_samples (target_id, ort, x, y, bssid, ssid, "
            "rssi, channel, band, is_own, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (target_id, ort or "", float(x), float(y), (bssid or "").lower(), ssid,
             rssi, channel, band, 1 if is_own else 0, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_wlan_heatmap_samples(self, target_id: Optional[int] = None) -> list[sqlite3.Row]:
        if target_id is None:
            return self._conn.execute(
                "SELECT * FROM wlan_heatmap_samples ORDER BY created_at").fetchall()
        return self._conn.execute(
            "SELECT * FROM wlan_heatmap_samples WHERE target_id=? OR target_id IS NULL "
            "ORDER BY created_at", (target_id,)).fetchall()

    def delete_wlan_heatmap_sample(self, sample_id: int) -> None:
        self._conn.execute(
            "DELETE FROM wlan_heatmap_samples WHERE id=?", (int(sample_id),))
        self._conn.commit()

    def clear_wlan_heatmap_samples(self, target_id: Optional[int] = None) -> int:
        if target_id is None:
            cur = self._conn.execute("DELETE FROM wlan_heatmap_samples")
        else:
            cur = self._conn.execute(
                "DELETE FROM wlan_heatmap_samples WHERE target_id=?", (target_id,))
        self._conn.commit()
        return cur.rowcount

    def set_wlan_floorplan(self, data_url: str, filename: str = "",
                           mime: str = "image/png",
                           target_id: Optional[int] = None) -> int:
        # Nur ein Grundriss pro target_id (bzw. global): alten entfernen.
        if target_id is None:
            self._conn.execute("DELETE FROM wlan_floorplans WHERE target_id IS NULL")
        else:
            self._conn.execute(
                "DELETE FROM wlan_floorplans WHERE target_id=?", (target_id,))
        cur = self._conn.execute(
            "INSERT INTO wlan_floorplans (target_id, filename, mime, data_url, created_at) "
            "VALUES (?,?,?,?,?)",
            (target_id, filename or "", mime or "image/png", data_url, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_wlan_floorplan(self, target_id: Optional[int] = None) -> Optional[sqlite3.Row]:
        if target_id is None:
            return self._conn.execute(
                "SELECT * FROM wlan_floorplans WHERE target_id IS NULL "
                "ORDER BY created_at DESC LIMIT 1").fetchone()
        return self._conn.execute(
            "SELECT * FROM wlan_floorplans WHERE target_id=? OR target_id IS NULL "
            "ORDER BY target_id DESC, created_at DESC LIMIT 1", (target_id,)).fetchone()

    def delete_wlan_floorplan(self, target_id: Optional[int] = None) -> None:
        if target_id is None:
            self._conn.execute("DELETE FROM wlan_floorplans WHERE target_id IS NULL")
        else:
            self._conn.execute(
                "DELETE FROM wlan_floorplans WHERE target_id=?", (target_id,))
        self._conn.commit()

    # ---------------- WLAN-Offensiv-Engagements (Autorisierungs-Record) ----------------
    def add_wlan_engagement(self, name: str, bssids: list, ssids: list,
                            start_ts: float, end_ts: float,
                            client_mac: str = "", location: str = "",
                            target_id: Optional[int] = None,
                            oversight: bool = False) -> int:
        cur = self._conn.execute(
            "INSERT INTO wlan_engagements (name, target_id, bssids, ssids, "
            "client_mac, location, start_ts, end_ts, oversight, revoked, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,0,?)",
            (name, target_id, json.dumps([str(b).lower() for b in (bssids or [])]),
             json.dumps([str(x) for x in (ssids or [])]),
             (client_mac or "").lower(), location, float(start_ts), float(end_ts),
             1 if oversight else 0, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_wlan_engagement(self, engagement_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM wlan_engagements WHERE id=?", (engagement_id,)
        ).fetchone()

    def list_wlan_engagements(self, include_revoked: bool = True) -> list[sqlite3.Row]:
        q = "SELECT * FROM wlan_engagements"
        if not include_revoked:
            q += " WHERE revoked=0"
        q += " ORDER BY created_at DESC"
        return self._conn.execute(q).fetchall()

    def set_wlan_engagement_oversight(self, engagement_id: int, confirmed: bool) -> None:
        self._conn.execute(
            "UPDATE wlan_engagements SET oversight=? WHERE id=?",
            (1 if confirmed else 0, engagement_id))
        self._conn.commit()

    def revoke_wlan_engagement(self, engagement_id: int) -> None:
        self._conn.execute(
            "UPDATE wlan_engagements SET revoked=1 WHERE id=?", (engagement_id,))
        self._conn.commit()

    # ---------------- WLAN-Offensiv-Credentials (NUR maskiert) ----------------
    def add_wlan_credential(self, engagement_id: int, kind: str,
                            masked: str = "", digest: str = "",
                            char_count: Optional[int] = None, bssid: str = "",
                            ssid: str = "", label: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO wlan_credentials (engagement_id, kind, bssid, ssid, label, "
            "masked, digest, char_count, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (engagement_id, kind, (bssid or "").lower(), ssid, label,
             masked, digest, char_count, _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def list_wlan_credentials(self, engagement_id: Optional[int] = None) -> list[sqlite3.Row]:
        if engagement_id is None:
            return self._conn.execute(
                "SELECT * FROM wlan_credentials ORDER BY created_at DESC").fetchall()
        return self._conn.execute(
            "SELECT * FROM wlan_credentials WHERE engagement_id=? ORDER BY created_at DESC",
            (engagement_id,)).fetchall()

    def purge_wlan_credentials(self, engagement_id: Optional[int] = None) -> int:
        if engagement_id is None:
            cur = self._conn.execute("DELETE FROM wlan_credentials")
        else:
            cur = self._conn.execute(
                "DELETE FROM wlan_credentials WHERE engagement_id=?", (engagement_id,))
        self._conn.commit()
        return cur.rowcount

    # ---------------- Replay / Checkpoint (scan_runs + scan_steps) ----------------
    def create_scan_run(self, run_id: str, target_id: int, phases=None,
                        meta: Optional[dict] = None, status: str = "running") -> str:
        self._conn.execute(
            "INSERT OR REPLACE INTO scan_runs (run_id, target_id, status, phases, "
            "meta, started_at, updated_at, finished_at) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, target_id, status, json.dumps(list(phases or [])),
             json.dumps(meta or {}), _now(), _now(), None),
        )
        self._conn.commit()
        return run_id

    def set_scan_run_status(self, run_id: str, status: str) -> None:
        fin = _now() if status in ("done", "error") else None
        self._conn.execute(
            "UPDATE scan_runs SET status=?, updated_at=?, "
            "finished_at=COALESCE(?, finished_at) WHERE run_id=?",
            (status, _now(), fin, run_id),
        )
        self._conn.commit()

    def get_scan_run(self, run_id: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM scan_runs WHERE run_id=?", (run_id,)).fetchone()

    def list_scan_runs(self, target_id: Optional[int] = None) -> list[sqlite3.Row]:
        if target_id is not None:
            return self._conn.execute(
                "SELECT * FROM scan_runs WHERE target_id=? ORDER BY started_at DESC",
                (target_id,)).fetchall()
        return self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC").fetchall()

    def add_scan_step(self, run_id: str, kind: str, payload: Optional[dict] = None,
                      phase: str = "", agent: str = "") -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(seq),0) AS m FROM scan_steps WHERE run_id=?",
            (run_id,)).fetchone()
        seq = int(row["m"]) + 1 if row else 1
        cur = self._conn.execute(
            "INSERT INTO scan_steps (run_id, seq, phase, agent, kind, payload, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (run_id, seq, phase, agent, kind, json.dumps(payload or {}), _now()),
        )
        self._conn.execute("UPDATE scan_runs SET updated_at=? WHERE run_id=?",
                           (_now(), run_id))
        self._conn.commit()
        return seq

    def list_scan_steps(self, run_id: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM scan_steps WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()

    def delete_scan_run(self, run_id: str) -> None:
        self._conn.execute("DELETE FROM scan_runs WHERE run_id=?", (run_id,))
        self._conn.commit()

    # ---------------- Reports ----------------
    def add_report(self, target_id: int, title: str, chain: dict,
                   cvss_score: Optional[float] = None, cvss_vector: str = "",
                   severity: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO reports (target_id, title, cvss_score, cvss_vector, "
            "severity, chain, created_at) VALUES (?,?,?,?,?,?,?)",
            (target_id, title, cvss_score, cvss_vector, severity,
             json.dumps(chain), _now()),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_report(self, report_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM reports WHERE id=?", (report_id,)
        ).fetchone()

    def list_reports(self, target_id: Optional[int] = None) -> list[sqlite3.Row]:
        if target_id is not None:
            return self._conn.execute(
                "SELECT * FROM reports WHERE target_id=? ORDER BY created_at DESC",
                (target_id,),
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM reports ORDER BY created_at DESC"
        ).fetchall()

    # ===================================================================
    # Neuronales-Gehirn: Node-/Log-Lesezugriffe + harte Lösch-/Reset-
    # Primitive. WICHTIG: Diese rohen DELETE/RESET-Primitive werden NUR
    # von antbb.brain_ops (human-gated, aus dem Web-UI) aufgerufen.
    # Soldaten/Queen/Service-Agenten-Fassade rufen sie NIE auf.
    # ===================================================================
    def get_finding(self, finding_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM findings WHERE id=?", (int(finding_id),)
        ).fetchone()

    def close_finding(self, finding_id: int, remediation_evidence: dict) -> bool:
        """Markiert einen Befund erst nach erfolgreichem Re-Check geschlossen."""
        row = self.get_finding(finding_id)
        if row is None:
            return False
        try:
            evidence = json.loads(row["evidence"] or "{}")
        except (TypeError, json.JSONDecodeError):
            evidence = {}
        evidence["remediation"] = remediation_evidence
        cur = self._conn.execute(
            "UPDATE findings SET category='blue-remediation-verified', status='GESCHLOSSEN', "
            "severity='info', evidence=? WHERE id=?",
            (json.dumps(evidence, ensure_ascii=False), int(finding_id)),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def count_findings(self, target_id: Optional[int] = None) -> int:
        if target_id is None:
            r = self._conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()
        else:
            r = self._conn.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE target_id=?",
                (int(target_id),)).fetchone()
        return int(r["c"]) if r else 0

    def count_scopes(self, target_id: int) -> int:
        r = self._conn.execute(
            "SELECT COUNT(*) AS c FROM scopes WHERE target_id=?",
            (int(target_id),)).fetchone()
        return int(r["c"]) if r else 0

    def list_logs(self, target_id: Optional[int] = None,
                  run_id: Optional[str] = None, limit: int = 200,
                  offset: int = 0) -> list[sqlite3.Row]:
        """Log-Zeilen = scan_steps (event|finding|phase|status), neueste zuerst.

        Optional nach Target (join scan_runs) oder Run gefiltert; paginiert.
        Reiner Lesezugriff."""
        q = ("SELECT st.*, r.target_id AS target_id FROM scan_steps st "
             "JOIN scan_runs r ON r.run_id = st.run_id")
        conds, args = [], []
        if run_id is not None:
            conds.append("st.run_id=?")
            args.append(str(run_id))
        if target_id is not None:
            conds.append("r.target_id=?")
            args.append(int(target_id))
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY st.created_at DESC, st.id DESC LIMIT ? OFFSET ?"
        args.extend([int(limit), int(offset)])
        return self._conn.execute(q, args).fetchall()

    def count_logs(self, target_id: Optional[int] = None,
                   run_id: Optional[str] = None) -> int:
        q = ("SELECT COUNT(*) AS c FROM scan_steps st "
             "JOIN scan_runs r ON r.run_id = st.run_id")
        conds, args = [], []
        if run_id is not None:
            conds.append("st.run_id=?")
            args.append(str(run_id))
        if target_id is not None:
            conds.append("r.target_id=?")
            args.append(int(target_id))
        if conds:
            q += " WHERE " + " AND ".join(conds)
        r = self._conn.execute(q, args).fetchone()
        return int(r["c"]) if r else 0

    def count_run_steps(self, run_id: str) -> int:
        r = self._conn.execute(
            "SELECT COUNT(*) AS c FROM scan_steps WHERE run_id=?",
            (str(run_id),)).fetchone()
        return int(r["c"]) if r else 0

    def delete_finding(self, finding_id: int) -> int:
        """Harte Löschung EINES Findings. Nur via brain_ops (human-gated)."""
        cur = self._conn.execute("DELETE FROM findings WHERE id=?",
                                 (int(finding_id),))
        self._conn.commit()
        return cur.rowcount

    def purge_logs(self, target_id: Optional[int] = None,
                   run_id: Optional[str] = None, all_logs: bool = False) -> int:
        """Harte Löschung von Log-Zeilen (scan_steps). Nur via brain_ops.

        all_logs=True leert ALLE scan_steps. Sonst scoped nach run_id und/oder
        target_id (letzteres via Sub-Select auf scan_runs)."""
        if all_logs:
            cur = self._conn.execute("DELETE FROM scan_steps")
            self._conn.commit()
            return cur.rowcount
        conds, args = [], []
        if run_id is not None:
            conds.append("run_id=?")
            args.append(str(run_id))
        if target_id is not None:
            conds.append("run_id IN (SELECT run_id FROM scan_runs WHERE target_id=?)")
            args.append(int(target_id))
        if not conds:
            return 0
        cur = self._conn.execute(
            "DELETE FROM scan_steps WHERE " + " AND ".join(conds), args)
        self._conn.commit()
        return cur.rowcount

    def reset_scan_run(self, run_id: str) -> dict:
        """Setzt EINEN laufenden/hängenden Lauf zurück: Status -> 'reset',
        finished_at gesetzt, unfertige Teil-Artefakte (scan_steps) verworfen.

        Fertige Läufe (done/error) werden NICHT verändert; Findings/Reports/
        Königin-Wissen bleiben unangetastet. Nur via brain_ops (human-gated)."""
        row = self.get_scan_run(run_id)
        if not row:
            return {"ok": False, "reason": "run_not_found", "run_id": run_id}
        status = row["status"]
        if status in ("done", "error", "reset"):
            return {"ok": False, "reason": "run_already_final",
                    "run_id": run_id, "status": status}
        steps = self.count_run_steps(run_id)
        self._conn.execute("DELETE FROM scan_steps WHERE run_id=?", (str(run_id),))
        self._conn.execute(
            "UPDATE scan_runs SET status='reset', updated_at=?, finished_at=? "
            "WHERE run_id=?", (_now(), _now(), str(run_id)))
        self._conn.commit()
        return {"ok": True, "run_id": run_id, "previous_status": status,
                "steps_discarded": steps}

    def list_stuck_runs(self) -> list[sqlite3.Row]:
        """Läufe, die nicht final sind (running|paused|queued|stuck)."""
        return self._conn.execute(
            "SELECT * FROM scan_runs WHERE status NOT IN ('done','error','reset') "
            "ORDER BY started_at DESC").fetchall()

    def wipe_operational(self) -> dict:
        """Harte Löschung ALLER operativen Daten (Targets samt CASCADE:
        Scopes/Findings/Reports/Scan-Historie/Oversight, plus WLAN-Daten).

        Das Königin-Wissen bleibt erhalten: capabilities (Registry),
        soldier_mems, soldier_overrides und settings werden NICHT berührt.
        Nur via brain_ops (human-gated)."""
        counts = {}
        for tbl in ("findings", "reports", "scopes", "scan_steps", "scan_runs",
                    "wlan_credentials", "wlan_engagements", "wlan_samples",
                    "wlan_heatmap_samples", "wlan_floorplans",
                    "oversight", "targets"):
            try:
                r = self._conn.execute(f"SELECT COUNT(*) AS c FROM {tbl}").fetchone()
                counts[tbl] = int(r["c"]) if r else 0
            except Exception:
                counts[tbl] = 0
        # targets-CASCADE räumt scopes/findings/reports/scan_runs/oversight mit ab;
        # WLAN-Samples/-Engagements/-Credentials sind teils target-los -> explizit.
        self._conn.execute("DELETE FROM wlan_credentials")
        self._conn.execute("DELETE FROM wlan_samples")
        self._conn.execute("DELETE FROM wlan_heatmap_samples")
        self._conn.execute("DELETE FROM wlan_floorplans")
        self._conn.execute("DELETE FROM wlan_engagements")
        self._conn.execute("DELETE FROM scan_steps")
        self._conn.execute("DELETE FROM scan_runs")
        self._conn.execute("DELETE FROM targets")  # CASCADE: scopes/findings/reports/oversight
        self._conn.commit()
        return counts


    # ---------------- Blue Queen Jobs ----------------
    def add_blue_job(self, name: str, kind: str, interval_sec: int = 86400,
                     target_id: Optional[int] = None, params: Optional[dict] = None,
                     enabled: bool = True) -> int:
        now = _now()
        cur = self._conn.execute(
            "INSERT INTO blue_jobs(name, kind, enabled, interval_sec, target_id, "
            "params_json, next_run_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (name, kind, 1 if enabled else 0, int(interval_sec), target_id,
             json.dumps(params or {}), now, now))
        self._conn.commit()
        return int(cur.lastrowid)

    def list_blue_jobs(self, enabled_only: bool = False) -> list:
        q = "SELECT * FROM blue_jobs"
        if enabled_only:
            q += " WHERE enabled=1"
        q += " ORDER BY id"
        return list(self._conn.execute(q).fetchall())

    def get_blue_job(self, job_id: int):
        return self._conn.execute(
            "SELECT * FROM blue_jobs WHERE id=?", (job_id,)).fetchone()

    def set_blue_job_enabled(self, job_id: int, enabled: bool) -> None:
        self._conn.execute("UPDATE blue_jobs SET enabled=? WHERE id=?",
                           (1 if enabled else 0, job_id))
        self._conn.commit()

    def delete_blue_job(self, job_id: int) -> None:
        self._conn.execute("DELETE FROM blue_jobs WHERE id=?", (job_id,))
        self._conn.commit()

    def mark_blue_job_ran(self, job_id: int, interval_sec: Optional[int] = None) -> None:
        now = _now()
        row = self.get_blue_job(job_id)
        iv = int(interval_sec if interval_sec is not None
                 else (row["interval_sec"] if row else 86400))
        self._conn.execute(
            "UPDATE blue_jobs SET last_run_at=?, next_run_at=? WHERE id=?",
            (now, now + iv, job_id))
        self._conn.commit()

    def due_blue_jobs(self, now: Optional[float] = None) -> list:
        now = now if now is not None else _now()
        return list(self._conn.execute(
            "SELECT * FROM blue_jobs WHERE enabled=1 AND "
            "(next_run_at IS NULL OR next_run_at<=?) ORDER BY id", (now,)).fetchall())

    def add_blue_job_run(self, job_id: int, run_id: str = "", status: str = "done",
                         finding_count: int = 0, closed_count: int = 0,
                         summary: Optional[dict] = None, error: str = "",
                         started_at: Optional[float] = None,
                         finished_at: Optional[float] = None) -> int:
        now = _now()
        cur = self._conn.execute(
            "INSERT INTO blue_job_runs(job_id, run_id, status, finding_count, "
            "closed_count, summary_json, error, started_at, finished_at, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (job_id, run_id, status, int(finding_count), int(closed_count),
             json.dumps(summary or {}), error or "",
             started_at or now, finished_at or now, now))
        self._conn.commit()
        return int(cur.lastrowid)

    def list_blue_job_runs(self, job_id: Optional[int] = None, limit: int = 50) -> list:
        if job_id is not None:
            return list(self._conn.execute(
                "SELECT * FROM blue_job_runs WHERE job_id=? ORDER BY id DESC LIMIT ?",
                (job_id, int(limit))).fetchall())
        return list(self._conn.execute(
            "SELECT * FROM blue_job_runs ORDER BY id DESC LIMIT ?",
            (int(limit),)).fetchall())



    # ---------------- Attack-Log (append-only) ----------------
    def append_attack_event(self, event: dict) -> int:
        """Append-only Persistenz. Kein Truncate/Delete über diese API."""
        import json as _json
        now = _now()
        cur = self._conn.execute(
            "INSERT INTO attack_events(event_type, source, action, countermeasure, "
            "outcome, before_json, after_json, evidence_json, run_id, target_id, "
            "severity, ts, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event.get("event_type") or "info",
             event.get("source") or "",
             event.get("action") or "",
             event.get("countermeasure") or "",
             event.get("outcome") or "",
             _json.dumps(event.get("before") or {}),
             _json.dumps(event.get("after") or {}),
             _json.dumps(event.get("evidence") or {}),
             event.get("run_id") or "",
             event.get("target_id"),
             event.get("severity") or "info",
             float(event.get("ts") or now),
             now))
        self._conn.commit()
        return int(cur.lastrowid)

    def list_attack_events(self, run_id=None, event_type=None,
                           limit: int = 200, since=None) -> list:
        import json as _json
        q = "SELECT * FROM attack_events WHERE 1=1"
        args = []
        if run_id:
            q += " AND run_id=?"; args.append(run_id)
        if event_type:
            q += " AND event_type=?"; args.append(event_type)
        if since is not None:
            q += " AND ts>=?"; args.append(float(since))
        q += " ORDER BY id DESC LIMIT ?"; args.append(int(limit))
        rows = list(self._conn.execute(q, args).fetchall())
        out = []
        for r in rows:
            d = dict(r)
            for k, jk in (("before", "before_json"), ("after", "after_json"),
                          ("evidence", "evidence_json")):
                try:
                    d[k] = _json.loads(d.get(jk) or "{}")
                except Exception:
                    d[k] = {}
            out.append(d)
        return out

    def count_attack_events(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS c FROM attack_events").fetchone()
        return int(row["c"] if row else 0)
