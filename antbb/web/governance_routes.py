"""HTTP-Fläche der Governance (Statusleiste, Audit, Kill Switch, Scope-Policy).

Routen hängen an der Kolonie-App (werden im Hub per colony_mount übernommen).
Die Kill-Switch-Middleware hängt an der App, die wirklich ausliefert (Hub:
api/main.py; Standalone: antbb/web/app.py).
"""
from __future__ import annotations

import logging
import re
import time
from typing import Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .. import governance as gov

log = logging.getLogger("antbb.governance.middleware")


def _user(request: Optional[Request]) -> dict:
    if request is None:
        return {}
    return getattr(request.state, "user", None) or {}


def _is_admin(request: Request) -> bool:
    from .. import hosted, webauth
    u = _user(request)
    role = (u.get("role") or "").strip().lower()
    if role == "admin":
        return True
    # Ohne Auth (lokaler Dev/Test, kein Hosted) gilt wie bisher: alles erlaubt.
    return not u and not hosted.enabled() and not webauth.auth_enabled()


def _can_kill(request: Request) -> bool:
    """Globaler Kill Switch + Reset: admin ODER member_plus (Cyber-Kollegen).
    Nur Benutzer-/Rollenverwaltung bleibt admin-exklusiv."""
    from .. import hosted, webauth
    u = _user(request)
    role = (u.get("role") or "").strip().lower()
    if role in ("admin", "member_plus"):
        return True
    # Ohne Auth (lokaler Dev/Test, kein Hosted) gilt wie bisher: alles erlaubt.
    return not u and not hosted.enabled() and not webauth.auth_enabled()


def _actor(request: Request) -> tuple[str, str]:
    u = _user(request)
    return (u.get("username") or "local"), (u.get("role") or "")


# Run-Start-Pfade (POST), die der Kill Switch blockiert.
RUN_START = (
    (re.compile(r"^/api/queens/(red|blue|yellow)/runs$"), "hub-run", "", None),
    (re.compile(r"^/api/targets/(\d+)/scan$"), "red-swarm", "Schwarm-Scan", "MEDIUM"),
    (re.compile(r"^/target/(\d+)/scan$"), "red-swarm", "Schwarm-Scan", "MEDIUM"),
    (re.compile(r"^/api/blue/run$"), "blue-queen", "Blue-Lauf", "LOW"),
    (re.compile(r"^/api/blue/jobs/(\d+)/run$"), "blue-jobs", "Blue-Job", "LOW"),
    (re.compile(r"^/api/blue/jobs/tick$"), "blue-jobs", "Blue-Job-Tick", "LOW"),
    (re.compile(r"^/api/blue/greenbone/scan$"), "blue-greenbone", "Greenbone-Scan", "MEDIUM"),
    (re.compile(r"^/api/blue/findings/(\d+)/apply$"), "blue-remediation", "Fix anwenden", "HIGH"),
    # Fix + Red-Re-Check (Brücke): startet einen eng begrenzten Lauf -> ebenfalls
    # vom Kill Switch gesperrt. Ohne Capture-Group: die ID ist eine Finding-ID,
    # keine Target-ID (Audit-Target bleibt leer statt falsch aufgelöst).
    (re.compile(r"^/api/blue/findings/\d+/remediate-recheck/?$"), "blue-remediation",
     "Fix + Re-Check", "HIGH"),
    (re.compile(r"^/(api/)?osint/run$"), "osint", "OSINT-Lauf", "SAFE"),
    (re.compile(r"^/yellow/upload$"), "yellow-queen", "RE-Analyse", "LOW"),
    (re.compile(r"^/api/wlan/offensive/[^/]+$"), "wlan", "WLAN offensiv", "HIGH"),
    (re.compile(r"^/api/wlan/full-scan$"), "wlan", "WLAN-Vollscan", "MEDIUM"),
    (re.compile(r"^/api/wlan/scan$"), "wlan", "WLAN-Scan", "SAFE"),
    (re.compile(r"^/api/wlan/esp-flash$"), "wlan", "ESP-Flash", "HIGH"),
    (re.compile(r"^/api/checkpoints/[^/]+/resume$"), "red-swarm", "Lauf fortsetzen", "MEDIUM"),
)
OVERSIGHT_PATHS = (re.compile(r"^/api/targets/(\d+)/oversight$"),
                   re.compile(r"^/target/(\d+)/oversight$"))


# Pfade, die die Middleware NIE blockiert (auch nicht fail-closed), damit die
# App bei einem Store-/Governance-Fehler erreichbar und wieder anmeldbar bleibt.
# Sie starten keine Läufe und überschneiden sich nicht mit RUN_START/OVERSIGHT.
FAIL_CLOSED_EXEMPT = (
    re.compile(r"^/api/health(/[^/]+)?/?$"),
    re.compile(r"^/(login|logout)/?$"),
    re.compile(r"^/static/"),
)

# Fehler beim Laden des Stores / Lesen des Kill-Switch-Status -> fail-closed.
# Gemeinsame Definition mit governance.py (identische Fehlerklassen).
_STATE_ERRORS = gov.KILL_STATE_ERRORS


def _is_exempt(path: str) -> bool:
    return any(rx.match(path or "") for rx in FAIL_CLOSED_EXEMPT)


def _kill_active_strict(store) -> bool:
    """Kill-Switch-Status STRIKT lesen (gemeinsame Hilfe gov.read_kill_state_strict).
    Wirft bei unlesbarem Status, damit die Middleware mit 503 fail-closed blockt
    (gov.kill_state() würde stattdessen "halted/unknown" liefern -> 423)."""
    return bool(gov.read_kill_state_strict(store).get("active"))


def _fail_closed_response(request: Request, path: str, store, actor: str, role: str,
                          kind: str, label: str, exc: BaseException):
    """Kontrolliert blocken (503), Fehlerfall loggen + auditieren (best effort)."""
    err = type(exc).__name__
    log.warning("Governance fail-closed: %s %s blockiert (%s: %s)", request.method, path, kind, err)
    gov.audit(store, actor=actor, role=role, agent="governance",
              action=label or "Lauf/Freigabe", risk="HIGH", result="blocked",
              detail=f"fail-closed: Governance-Status nicht lesbar ({kind}: {err})")
    detail = ("Governance-/Kill-Switch-Status nicht lesbar: Anfrage aus Sicherheitsgründen "
              "blockiert (fail-closed). Bitte Admin informieren.")
    if "text/html" in (request.headers.get("accept") or "") and not path.startswith("/api"):
        from fastapi.responses import HTMLResponse
        return HTMLResponse(f"<h2>⛔ Blockiert</h2><pre>{detail}</pre><a href=\"/\">Zurück</a>",
                            status_code=503)
    return JSONResponse({"detail": detail, "fail_closed": True, "kill_switch": "unknown"},
                        status_code=503)


def _match_run(path: str):
    for rx, agent, label, risk in RUN_START:
        m = rx.match(path)
        if m:
            return m, agent, label, risk
    return None


def _target_name(store, m) -> tuple[str, Optional[int]]:
    try:
        tid = int(m.group(1))
    except (IndexError, ValueError, TypeError):
        return "", None
    t = store.get_target(tid)
    return (t["name"] if t is not None else f"#{tid}"), tid


def install_middleware(app: FastAPI, store_getter=None) -> None:
    getter = store_getter or gov.default_store

    @app.middleware("http")
    async def governance_guard(request: Request, call_next):
        path = request.url.path
        method = request.method.upper()
        if method != "POST" or _is_exempt(path):
            return await call_next(request)
        hit = _match_run(path)
        ovs = None if hit else next((rx.match(path) for rx in OVERSIGHT_PATHS if rx.match(path)), None)
        if not hit and not ovs:
            return await call_next(request)
        actor, role = _actor(request)
        label = hit[2] if hit else "Oversight-Freigabe"
        # fail-closed: Store nicht ladbar -> NICHT durchlassen. Unerwartete
        # Fehler außerhalb _STATE_ERRORS werden nicht gefangen und enden als
        # 500 – ebenfalls ohne den Request weiterzureichen.
        try:
            store = getter()
            if store is None:
                raise RuntimeError("kein Store")
        except _STATE_ERRORS as exc:
            return _fail_closed_response(request, path, None, actor, role,
                                         "store", label, exc)
        if hit:
            m, agent, label, risk = hit
            try:
                halted = _kill_active_strict(store)
            except _STATE_ERRORS as exc:
                return _fail_closed_response(request, path, store, actor, role,
                                             "kill_switch", label, exc)
            if halted:
                target, tid = ("", None) if agent in ("hub-run",) else _target_name(store, m)
                gov.audit(store, actor=actor, role=role, agent=agent,
                          action=label or f"Lauf {m.group(1)}", target=target, target_id=tid,
                          risk=risk or "", result="blocked", detail="Kill Switch aktiv")
                detail = ("KILL SWITCH aktiv: alle Agenten gestoppt, keine neuen Läufe bis "
                          "zum Reset durch den Admin.")
                if "text/html" in (request.headers.get("accept") or "") and not path.startswith("/api"):
                    from fastapi.responses import HTMLResponse
                    return HTMLResponse(f"<h2>⛔ Blockiert</h2><pre>{detail}</pre><a href=\"/\">Zurück</a>",
                                        status_code=423)
                return JSONResponse({"detail": detail, "kill_switch": True}, status_code=423)
            response = await call_next(request)
            if getattr(request.state, "gov_audited", False):
                return response
            code = int(getattr(response, "status_code", 200) or 200)
            result = ("started" if code < 400 else "denied" if code in (401, 403) else
                      "blocked" if code == 423 else "refused" if code in (409, 429) else
                      "error" if code >= 500 else f"http-{code}")
            target, tid = ("", None) if agent == "hub-run" else _target_name(store, m)
            gov.audit(store, actor=actor, role=role, agent=agent,
                      action=label or f"Lauf {m.group(1)}", target=target, target_id=tid,
                      risk=risk or "", result=result, detail=f"HTTP {code}")
            return response
        response = await call_next(request)
        code = int(getattr(response, "status_code", 200) or 200)
        target, tid = _target_name(store, ovs)
        confirmed = bool(tid and store.is_confirmed(tid))
        gov.audit(store, actor=actor, role=role, agent="human-oversight",
                  action="Freigabe erteilt" if confirmed else "Freigabe entzogen/fehlt",
                  target=target, target_id=tid, risk="HIGH",
                  result=("approved" if confirmed else "denied") if code < 400 else f"http-{code}")
        return response


def install_routes(app: FastAPI, svc, *, running_state=None, visible_targets=None) -> None:
    """svc: AntBBService der Kolonie. running_state(): dict mit status/target_id."""

    def _store():
        return svc.store

    @app.get("/api/governance/status")
    def governance_status(request: Request):
        user = _user(request)
        vis = visible_targets(request) if visible_targets else None
        run = running_state() if running_state else None
        return gov.status(_store(), user=user, visible_targets=vis, running=run)

    @app.get("/api/governance/audit")
    def governance_audit(request: Request, limit: int = 12):
        full = _is_admin(request)
        return {"entries": gov.list_audit(_store(), limit=limit, full=full),
                "masked": not full}

    @app.get("/api/governance/risk")
    def governance_risk():
        return {"levels": gov.RISK_TABLE, "techniques": gov.TECHNIQUES,
                "critical": gov.CRITICAL_TECHNIQUES}

    @app.post("/api/governance/kill")
    def governance_kill(request: Request, payload: Optional[dict] = None):
        if not _can_kill(request):
            raise HTTPException(403, "Kill Switch: nur Admin oder member_plus.")
        payload = payload or {}
        if str(payload.get("confirm") or "").strip().upper() != "STOP":
            raise HTTPException(400, "Bestätigung fehlt: confirm='STOP'.")
        actor, role = _actor(request)
        request.state.gov_audited = True
        st = gov.activate_kill(_store(), actor=actor, role=role,
                               reason=str(payload.get("reason") or ""))
        return {"ok": True, "kill_switch": "active", "stopped": st.get("stopped", []),
                "notified": st.get("notified", False)}

    @app.post("/api/governance/reset")
    def governance_reset(request: Request, payload: Optional[dict] = None):
        if not _can_kill(request):
            raise HTTPException(403, "Kill-Switch-Reset: nur Admin oder member_plus.")
        payload = payload or {}
        if str(payload.get("confirm") or "").strip().upper() != "RESET":
            raise HTTPException(400, "Bestätigung fehlt: confirm='RESET'.")
        actor, role = _actor(request)
        gov.reset_kill(_store(), actor=actor, role=role)
        return {"ok": True, "kill_switch": "ready"}

    @app.get("/api/targets/{target_id}/policy")
    def api_get_policy(target_id: int):
        pol = gov.get_policy(_store(), target_id)
        if pol is None:
            raise HTTPException(404, "Unbekanntes Ziel.")
        pol["techniques_catalog"] = gov.TECHNIQUES
        return pol

    def _save(request: Request, target_id: int, payload: dict):
        actor, role = _actor(request)
        from .. import hosted, webauth
        if hosted.is_guest(role):
            raise HTTPException(403, "Der Gast darf die Scope-Policy nicht ändern.")
        # Formale Scope-Autorisierung: nur admin/member_plus. Einfaches member
        # bleibt wie bisher eingeschraenkt (nur Basis-Scope kind/value).
        if not webauth.can_authorize_scope(role) and (hosted.enabled() or webauth.auth_enabled()):
            raise HTTPException(403, "Scope-Autorisierung: nur Admin oder member_plus.")
        try:
            return gov.save_policy(_store(), target_id, payload, actor=actor, role=role)
        except KeyError:
            raise HTTPException(404, "Unbekanntes Ziel.")
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.put("/api/targets/{target_id}/policy")
    def api_put_policy(request: Request, target_id: int, payload: dict):
        return _save(request, target_id, payload)

    @app.post("/target/{target_id}/policy")
    async def html_policy(request: Request, target_id: int):
        form = await request.form()
        payload = {k: form.get(k, "") for k in (
            "target_domains", "allowed_cidrs", "allowed_ports", "max_requests_per_minute",
            "max_concurrent_agents", "test_window_start", "test_window_end", "authorized_by",
            "authorization_document", "emergency_contact", "rules_of_engagement",
            "audit_retention_days", "kill_switch")}
        payload["allowed_techniques"] = form.getlist("allowed_techniques")
        payload["approval_required_for"] = form.getlist("approval_required_for")
        try:
            _save(request, target_id, payload)
        except HTTPException as exc:
            import html as _html
            from fastapi.responses import HTMLResponse
            return HTMLResponse(f"<h2>⛔ Scope-Policy nicht gespeichert</h2><pre>{_html.escape(str(exc.detail))}</pre>"
                                f'<a href="/target/{target_id}#policy">Zurück</a>',
                                status_code=exc.status_code)
        return RedirectResponse(f"/target/{target_id}#policy", status_code=303)
