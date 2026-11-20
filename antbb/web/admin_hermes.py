"""Admin-Chat mit dem lokalen Hermes Agent (/admin/hermes).

* Nur Rolle admin (webguard._ADMIN_ONLY fuer /admin/* und /api/admin/*, hier
  zusaetzlich serverseitig geprueft) UND ein aktiver, zeitlich begrenzter
  Grant, den sich der Admin selbst erteilt (Standard 30 min, max. 120 min).
* Hermes laeuft auf dem Host nur auf 127.0.0.1:8642 (Container: network_mode
  host). Der Bearer-Key wird serverseitig aus der Datei gelesen
  (HERMES_API_KEY_FILE, read-only gemountet) und NIE an den Browser gegeben.
* Jede Anfrage wird mit Benutzer, Laenge und Dauer im Aktivitaetslog
  vermerkt (ohne Key; Prompt nur gekuerzt).
* Nicht-Streaming-Aufruf: gefaehrliche Befehle lehnt Hermes ohne Rueckfrage
  ab (approvals.unattended_mode: deny); harte Sperrmuster gelten immer.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import time
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .. import webauth

log = logging.getLogger("antbb.admin")

GRANT_KEY = "hermes.grant."          # + username -> "expiry_ts:conversation"
DEFAULT_MINUTES = 30
MAX_MINUTES = 120
MAX_PROMPT = 4000
TIMEOUT = float(os.environ.get("ANTBB_HERMES_TIMEOUT", "600"))
_LOCK = asyncio.Lock()               # ein Lauf gleichzeitig (4 CPU-Kerne)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _base_url() -> str:
    try:
        from .. import llm
        p = llm.PROVIDERS.get("hermes")
        if p and p.base_url:
            return p.base_url.rstrip("/")
    except Exception:  # noqa: BLE001
        pass
    return "http://127.0.0.1:8642/v1"


def _api_key() -> str:
    try:
        from .. import llm
        p = llm.PROVIDERS.get("hermes")
        return (llm._read_key(p) or "") if p else ""
    except Exception:  # noqa: BLE001
        return ""


def _require_admin(request: Request) -> dict:
    user = getattr(request.state, "user", None) or {}
    if not webauth.is_admin(user.get("role")):
        raise HTTPException(403, "Only an admin may run this action.")
    return user


def _grant(store, username: str) -> dict:
    raw = ""
    try:
        raw = store.get_setting(GRANT_KEY + username, "") or ""
    except Exception:  # noqa: BLE001
        raw = ""
    exp, _, conv = raw.partition(":")
    try:
        exp_f = float(exp)
    except ValueError:
        exp_f = 0.0
    left = int(exp_f - time.time())
    return {"active": left > 0, "expires_at": exp_f, "seconds_left": max(0, left),
            "conversation": conv if left > 0 else ""}


def _set_grant(store, username: str, minutes: int) -> dict:
    if minutes <= 0:
        store.set_setting(GRANT_KEY + username, "0:")
    else:
        conv = f"antbb-{username}-{int(time.time())}-{secrets.token_hex(4)}"
        store.set_setting(GRANT_KEY + username, f"{time.time() + minutes * 60:.0f}:{conv}")
    return _grant(store, username)


def _extract(data: dict) -> tuple[str, list[dict]]:
    text_parts: list[str] = []
    tools: list[dict] = []
    for item in (data or {}).get("output", []) or []:
        typ = item.get("type")
        if typ == "message" and item.get("phase") != "commentary":
            for c in item.get("content", []) or []:
                if c.get("type") in ("output_text", "text") and c.get("text"):
                    text_parts.append(c["text"])
        elif typ == "function_call":
            tools.append({"name": str(item.get("name", ""))[:60],
                          "arguments": str(item.get("arguments", ""))[:400]})
        elif typ == "function_call_output" and tools:
            tools[-1]["output"] = str(item.get("output", ""))[:600]
    return "\n".join(text_parts).strip(), tools


def register(app: FastAPI, templates, store_getter: Callable[[], Any]) -> None:

    def _audit(request: Request, kind: str, detail: str, status: int | None = None) -> None:
        try:
            from .activity import record
            record(store_getter(), request, kind, detail=detail, status=status)
        except Exception:  # noqa: BLE001
            pass
        log.info("audit %s by=%s %s", kind,
                 (getattr(request.state, "user", None) or {}).get("username"), detail)

    @app.get("/admin/hermes", response_class=HTMLResponse, include_in_schema=False)
    def admin_hermes(request: Request):
        user = _require_admin(request)
        return templates.TemplateResponse(request, "admin_hermes.html", {
            "grant": _grant(store_getter(), user.get("username", "")),
            "configured": bool(_api_key()),
            "default_minutes": DEFAULT_MINUTES, "max_minutes": MAX_MINUTES,
            "timeout": int(TIMEOUT)})

    @app.get("/api/admin/hermes/grant", include_in_schema=False)
    def api_hermes_grant_get(request: Request):
        user = _require_admin(request)
        return _grant(store_getter(), user.get("username", ""))

    @app.post("/api/admin/hermes/grant", include_in_schema=False)
    async def api_hermes_grant(request: Request):
        user = _require_admin(request)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        try:
            minutes = int((body or {}).get("minutes", DEFAULT_MINUTES))
        except (TypeError, ValueError):
            minutes = DEFAULT_MINUTES
        minutes = max(0, min(MAX_MINUTES, minutes))
        g = _set_grant(store_getter(), user.get("username", ""), minutes)
        _audit(request, "hermes_grant" if minutes else "hermes_grant_end",
               f"{minutes} min" if minutes else "beendet")
        return g

    @app.post("/api/admin/hermes/chat", include_in_schema=False)
    async def api_hermes_chat(request: Request):
        user = _require_admin(request)
        username = user.get("username", "")
        g = _grant(store_getter(), username)
        if not g["active"]:
            _audit(request, "hermes_denied", "kein aktiver Grant", 403)
            return JSONResponse({"error": "Kein aktiver Zugriff. Bitte zuerst freigeben."},
                                status_code=403)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        msg = _CTRL.sub("", str((body or {}).get("message") or "")).strip()
        if not msg:
            return JSONResponse({"error": "Leere Nachricht."}, status_code=400)
        if len(msg) > MAX_PROMPT:
            return JSONResponse({"error": f"Nachricht zu lang (max. {MAX_PROMPT} Zeichen)."},
                                status_code=400)
        key = _api_key()
        if not key:
            return JSONResponse({"error": "Hermes ist nicht konfiguriert."}, status_code=503)
        if _LOCK.locked():
            return JSONResponse({"error": "Hermes bearbeitet gerade eine andere Anfrage."},
                                status_code=429)
        import httpx
        preview = msg[:120].replace("\n", " ")
        t0 = time.time()
        async with _LOCK:
            try:
                async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                    r = await client.post(
                        _base_url() + "/responses",
                        headers={"Authorization": f"Bearer {key}",
                                 "Content-Type": "application/json"},
                        json={"model": "hermes", "input": msg, "store": True,
                              "conversation": g["conversation"]})
            except Exception as exc:  # noqa: BLE001
                dur = time.time() - t0
                _audit(request, "hermes_chat", f"Fehler {type(exc).__name__} nach {dur:.0f}s · {preview}", 504)
                return JSONResponse({"error": "Hermes hat nicht rechtzeitig geantwortet."},
                                    status_code=504)
        dur = time.time() - t0
        if r.status_code != 200:
            _audit(request, "hermes_chat", f"HTTP {r.status_code} nach {dur:.0f}s · {preview}", 502)
            return JSONResponse({"error": f"Hermes-Fehler (HTTP {r.status_code})."}, status_code=502)
        try:
            data = r.json()
        except Exception:  # noqa: BLE001
            data = {}
        text, tools = _extract(data)
        status = str(data.get("status") or "")
        _audit(request, "hermes_chat",
               f"{len(msg)} Zeichen, {len(tools)} Werkzeug(e), {dur:.0f}s, {status} · {preview}", 200)
        return {"reply": text or "(keine Antwort)", "tools": tools, "status": status,
                "seconds": round(dur, 1)}
