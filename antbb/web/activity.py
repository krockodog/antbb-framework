"""Aktivitaets-Log (append-only) + Sitzungs-Metadaten fuer /admin/activity.

* Tabelle ``activity_events``: Login ok/fehlgeschlagen (Benutzername wie
  eingegeben, NIE Passwoerter), Logout, Rate-Limit, 2FA, Admin-Seitenaufrufe
  und -Aenderungen, Einladungen, Ollama-Modellwechsel. Nur INSERT, kein
  UPDATE/DELETE. Aufbewahrung: ANTBB_ACTIVITY_RETENTION_DAYS (Default 90) –
  derzeit nur als Hinweis angezeigt, es wird nichts geloescht.
* Tabelle ``session_meta``: IP, User-Agent (gekuerzt), letzte Aktivitaet je
  Sitzung, Schluessel ist SHA-256 des Session-Tokens (Token selbst nie hier).
* Pfade werden ohne Query gespeichert; /invite/<token> wird maskiert.
* Alle Funktionen fangen Fehler ab: der Request blockiert/scheitert nie.
"""
from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from typing import Any, Optional

_LOCK = threading.Lock()
_TOUCH: dict[str, float] = {}
TOUCH_EVERY = 60.0

SCHEMA = """
CREATE TABLE IF NOT EXISTS activity_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    kind      TEXT NOT NULL,
    username  TEXT,
    role      TEXT,
    ip        TEXT DEFAULT '',
    method    TEXT DEFAULT '',
    path      TEXT DEFAULT '',
    status    INTEGER,
    detail    TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_activity_ts ON activity_events(ts);
CREATE TABLE IF NOT EXISTS session_meta (
    sid        TEXT PRIMARY KEY,
    username   TEXT,
    ip         TEXT DEFAULT '',
    ua         TEXT DEFAULT '',
    created_at REAL,
    last_seen  REAL
);
"""

_INVITE = re.compile(r"(/invite/)[A-Za-z0-9_-]+")
_TOKENISH = re.compile(r"[A-Za-z0-9_-]{24,}")


def retention_days() -> int:
    try:
        return max(1, int(os.environ.get("ANTBB_ACTIVITY_RETENTION_DAYS", "90")))
    except ValueError:
        return 90


def _conn(store):
    conn = store._conn  # noqa: SLF001 – gleicher SQLite-Store wie der Rest
    if getattr(store, "_activity_schema_conn", None) is not conn:
        with _LOCK:
            if getattr(store, "_activity_schema_conn", None) is not conn:
                conn.executescript(SCHEMA)
                conn.commit()
                store._activity_schema_conn = conn
    return conn


def mask_path(path: str) -> str:
    p = _INVITE.sub(r"\1…", path or "")
    p = _TOKENISH.sub("…", p)
    return p[:200]


def client_ip(request) -> str:
    # uvicorn wertet X-Forwarded-For nur von FORWARDED_ALLOW_IPS=127.0.0.1
    # (Caddy) aus; request.client ist damit bereits die echte Client-IP.
    try:
        return (request.client.host if request.client else "")[:64]
    except Exception:  # noqa: BLE001
        return ""


def short_ua(request) -> str:
    ua = (request.headers.get("user-agent") or "")
    for name in ("Edg", "Firefox", "Chrome", "Safari", "curl", "python-httpx", "Wget"):
        if name in ua:
            os_ = next((o for o in ("Android", "iPhone", "iPad", "Windows", "Mac OS", "Linux") if o in ua), "")
            return f"{'Edge' if name == 'Edg' else name}{' · ' + os_ if os_ else ''}"[:60]
    return ua[:60]


def record(store, request=None, kind: str = "", *, username: Optional[str] = None,
           role: Optional[str] = None, status: Optional[int] = None, detail: str = "") -> None:
    try:
        user = (getattr(getattr(request, "state", None), "user", None) or {}) if request is not None else {}
        conn = _conn(store)
        conn.execute(
            "INSERT INTO activity_events (ts, kind, username, role, ip, method, path, status, detail) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (time.time(), kind[:40], (username if username is not None else user.get("username")) or None,
             (role if role is not None else user.get("role")) or None,
             client_ip(request) if request is not None else "",
             (request.method if request is not None else "")[:8],
             mask_path(request.url.path) if request is not None else "",
             status, (detail or "")[:300]))
        conn.commit()
    except Exception:  # noqa: BLE001
        pass


def _sid(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def touch_session(store, request, token: str, username: str) -> None:
    """Letzte Aktivitaet je Sitzung, hoechstens einmal pro Minute geschrieben."""
    if not token:
        return
    sid = _sid(token)
    now = time.time()
    if now - _TOUCH.get(sid, 0.0) < TOUCH_EVERY:
        return
    _TOUCH[sid] = now
    try:
        conn = _conn(store)
        conn.execute(
            "INSERT INTO session_meta (sid, username, ip, ua, created_at, last_seen) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(sid) DO UPDATE SET last_seen=excluded.last_seen, ip=excluded.ip, ua=excluded.ua",
            (sid, username, client_ip(request), short_ua(request), now, now))
        conn.commit()
    except Exception:  # noqa: BLE001
        pass


def session_last_seen(store, token: str) -> Optional[float]:
    try:
        row = _conn(store).execute("SELECT last_seen FROM session_meta WHERE sid=?",
                                   (_sid(token),)).fetchone()
        return float(row["last_seen"]) if row and row["last_seen"] else None
    except Exception:  # noqa: BLE001
        return None


def active_sessions(store) -> list[dict]:
    conn = _conn(store)
    rows = conn.execute("SELECT token, username, role, created_at, expires_at FROM sessions "
                        "WHERE expires_at > ? ORDER BY created_at DESC", (time.time(),)).fetchall()
    out = []
    for r in rows:
        m = conn.execute("SELECT ip, ua, last_seen FROM session_meta WHERE sid=?",
                         (_sid(r["token"]),)).fetchone()
        out.append({"username": r["username"], "role": r["role"], "since": r["created_at"],
                    "expires_at": r["expires_at"],
                    "last_seen": (m["last_seen"] if m else None), "ip": (m["ip"] if m else ""),
                    "ua": (m["ua"] if m else "")})
    return out


LOGIN_KINDS = ("login_ok", "login_failed", "login_limited", "logout", "2fa_ok", "2fa_failed",
               "2fa_limited", "2fa_enabled", "2fa_disabled", "password_changed")


def events(store, *, kinds=None, exclude=None, username: Optional[str] = None,
           limit: int = 200) -> list[dict]:
    sql = "SELECT * FROM activity_events"
    cond, args = [], []
    if kinds:
        cond.append("kind IN (%s)" % ",".join("?" for _ in kinds)); args += list(kinds)
    if exclude:
        cond.append("kind NOT IN (%s)" % ",".join("?" for _ in exclude)); args += list(exclude)
    if username:
        cond.append("username=?"); args.append(username)
    if cond:
        sql += " WHERE " + " AND ".join(cond)
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(int(limit))
    return [dict(r) for r in _conn(store).execute(sql, args).fetchall()]
