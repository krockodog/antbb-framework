"""Admin-Portal: Benutzerverwaltung + Einladungen (E-Mail oder Link).

* /admin, /admin/users, /api/users… sind admin-only (webguard._needs_admin,
  zusaetzlich hier serverseitig geprueft). member bekommt 403.
* /invite/<token> ist oeffentlich (wie /login): die eingeladene Person waehlt
  Benutzername (falls nicht vorgegeben) und Passwort selbst. Kein Default-
  Passwort, kein Klartext in DB/Logs – nur PBKDF2 via webauth.
* Widerruf ist weich (revoked=1). Benutzer werden nie geloescht, nur deaktiviert.
* SMTP ist optional (ANTBB_SMTP_HOST/PORT/USER/PASSWORD/FROM aus der Umgebung).
  Ohne SMTP genuegen Kopier-Link und mailto:.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import time
from typing import Any, Callable, Optional
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .. import webauth

log = logging.getLogger("antbb.admin")

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s<>\"']{1,64}@[^@\s<>\"']{1,190}\.[A-Za-z]{2,}$")
MIN_PASSWORD = 10
MAX_DAYS = 30


def _short(token: str) -> str:
    return (token or "")[:6] + "…"


def _user(request: Request) -> dict:
    return getattr(request.state, "user", None) or {}


def _require_admin(request: Request) -> dict:
    user = _user(request)
    if not webauth.is_admin(user.get("role")):
        raise HTTPException(403, "Nur ein Admin darf Benutzer verwalten.")
    return user


def _base_url(request: Request) -> str:
    env = os.environ.get("ANTBB_PUBLIC_URL", "").strip().rstrip("/")
    if env:
        return env
    from .. import hosted
    host = request.headers.get("host") or request.url.netloc
    scheme = "https" if hosted.enabled() else request.url.scheme
    return f"{scheme}://{host}"


def invite_status(row) -> str:
    if row["revoked"]:
        return "revoked"
    if row["used_at"]:
        return "used"
    if float(row["expires_at"]) < time.time():
        return "expired"
    return "pending"


def _invite_dict(row, *, with_token: bool = False) -> dict:
    d = {
        "ref": row["ref"],
        "email": row["email"],
        "username": row["username"],
        "role": row["role"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "used_at": row["used_at"],
        "used_by": row["used_by"],
        "status": invite_status(row),
    }
    if with_token:
        d["token"] = row["token"]
    return d


def _mailto(email: str, url: str, role: str) -> str:
    subject = "Einladung zu antbb · All and One"
    body = (
        "Hallo,\n\n"
        f"du wurdest zu antbb (All and One) eingeladen. Rolle: {role}.\n"
        "Lege dein Passwort selbst fest über diesen Link:\n\n"
        f"{url}\n\n"
        "Der Link ist nur einmal gültig und läuft ab.\n"
    )
    return f"mailto:{quote(email)}?subject={quote(subject)}&body={quote(body)}"


def _smtp_configured() -> bool:
    return bool(os.environ.get("ANTBB_SMTP_HOST", "").strip())


def _send_smtp(email: str, url: str, role: str) -> tuple[bool, str]:
    """Optionaler Versand. Fehler brechen die Einladung nicht ab."""
    if not _smtp_configured():
        return False, "SMTP nicht konfiguriert – Link kopieren oder mailto nutzen."
    import smtplib
    import ssl
    from email.message import EmailMessage

    host = os.environ.get("ANTBB_SMTP_HOST", "").strip()
    port = int(os.environ.get("ANTBB_SMTP_PORT", "587") or 587)
    user = os.environ.get("ANTBB_SMTP_USER", "").strip()
    password = os.environ.get("ANTBB_SMTP_PASSWORD", "")
    sender = os.environ.get("ANTBB_SMTP_FROM", "").strip() or user
    if not sender:
        return False, "ANTBB_SMTP_FROM fehlt."
    msg = EmailMessage()
    msg["Subject"] = "Einladung zu antbb · All and One"
    msg["From"] = sender
    msg["To"] = email
    msg.set_content(
        "Hallo,\n\n"
        f"du wurdest zu antbb (All and One) eingeladen. Rolle: {role}.\n"
        f"Passwort selbst festlegen: {url}\n\n"
        "Der Link ist nur einmal gültig und läuft ab.\n"
    )
    try:
        ctx = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=12, context=ctx) as s:
                if user:
                    s.login(user, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=12) as s:
                s.starttls(context=ctx)
                if user:
                    s.login(user, password)
                s.send_message(msg)
        return True, f"E-Mail an {email} versendet."
    except Exception as exc:  # noqa: BLE001
        log.warning("invite smtp failed: %s", type(exc).__name__)
        return False, f"E-Mail-Versand fehlgeschlagen ({type(exc).__name__}). Link manuell weitergeben."


# ---- Kernlogik (auch fuer Tests/API) --------------------------------------
def create_invite(store, *, created_by: str, role: str = "member", email: str = "",
                  username: str = "", days: int = 7, confirm_admin: bool = False) -> dict:
    role = (role or "member").strip().lower()
    if role not in webauth.ROLES:
        raise ValueError("Unbekannte Rolle.")
    if role == "admin" and not confirm_admin:
        raise ValueError("Admin-Einladung bitte ausdrücklich bestätigen.")
    email = (email or "").strip().lower()
    if email and not EMAIL_RE.match(email):
        raise ValueError("E-Mail-Adresse ist ungültig.")
    username = (username or "").strip()
    if username:
        if not USERNAME_RE.match(username):
            raise ValueError("Benutzername: 3–64 Zeichen, Buchstaben/Ziffern . _ @ -")
        if store.get_user(username):
            raise ValueError("Benutzername ist bereits vergeben.")
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = 7
    days = max(1, min(MAX_DAYS, days))
    token = secrets.token_urlsafe(32)
    ref = secrets.token_hex(4)
    store.create_invite(token, ref, role, created_by, email=email,
                        username=username, ttl_seconds=days * 86400)
    log.info("invite created ref=%s role=%s by=%s token=%s", ref, role, created_by, _short(token))
    return {"token": token, "ref": ref, "role": role, "email": email,
            "username": username, "days": days}


def accept_invite(store, token: str, username: str, password: str, confirm: str):
    """Gibt (user_row, None) oder (None, fehlertext) zurueck."""
    row = store.get_invite(token)
    if not row or invite_status(row) != "pending":
        return None, "Einladung ist ungültig, abgelaufen, widerrufen oder schon benutzt."
    fixed = (row["username"] or "").strip()
    username = fixed or (username or "").strip()
    if not USERNAME_RE.match(username or ""):
        return None, "Benutzername: 3–64 Zeichen, Buchstaben/Ziffern . _ @ -"
    if len(password or "") < MIN_PASSWORD:
        return None, f"Passwort muss mindestens {MIN_PASSWORD} Zeichen haben."
    if password != confirm:
        return None, "Passwörter stimmen nicht überein."
    if password.strip().lower() == username.lower():
        return None, "Passwort darf nicht dem Benutzernamen entsprechen."
    if store.get_user(username):
        return None, "Benutzername ist bereits vergeben."
    if not store.claim_invite(token, username):
        return None, "Einladung ist ungültig, abgelaufen, widerrufen oder schon benutzt."
    try:
        webauth.create_user(store, username, password, role=row["role"])
    except Exception:  # noqa: BLE001 – z. B. UNIQUE-Konflikt im Rennen
        store.release_invite(token)
        return None, "Benutzer konnte nicht angelegt werden (Name vergeben?)."
    log.info("invite accepted ref=%s user=%s role=%s", row["ref"], username, row["role"])
    return store.get_user(username), None


def change_user(store, actor: str, username: str, *, role: Optional[str] = None,
                active: Optional[bool] = None) -> Optional[str]:
    """Rolle/Aktiv aendern. Gibt Fehlertext oder None zurueck."""
    row = store.get_user(username)
    if not row:
        return "Benutzer nicht gefunden."
    is_admin_now = row["role"] == "admin" and bool(row["active"])
    if role is not None:
        role = role.strip().lower()
        if role not in webauth.ROLES:
            return "Unbekannte Rolle."
        if is_admin_now and role != "admin" and store.count_active_admins() <= 1:
            return "Der letzte aktive Admin kann nicht herabgestuft werden."
    if active is not None and not active:
        if username == actor:
            return "Du kannst dein eigenes Konto nicht deaktivieren."
        if is_admin_now and store.count_active_admins() <= 1:
            return "Der letzte aktive Admin kann nicht deaktiviert werden."
    if role is not None and role != row["role"]:
        store.set_user_role(username, role)
        log.info("user role changed user=%s role=%s by=%s", username, role, actor)
    if active is not None and bool(active) != bool(row["active"]):
        store.set_user_active(username, bool(active))
        log.info("user active=%s user=%s by=%s", int(bool(active)), username, actor)
    return None


# ---- Admin-Hinweis (blinkender Punkt am Admin-Link) ------------------------
# Der Punkt blinkt NUR bei (1) neuen Benutzern (Konto angelegt / Erst-Login)
# oder (2) kritischen Ereignissen (Login-Rate-Limit/Bruteforce, Serverfehler,
# gesperrte Konten) seit dem letzten "gesehen" des jeweiligen Admins.
# Offene Alarme allgemein und Oversight-Eintraege loesen ihn nicht aus.
# Nichts wird geloescht; "gesehen" ist nur ein Zeitstempel pro Admin.
ATTENTION_ALERT_KINDS = ("login_limited", "login_bruteforce_2fa", "server_error")
ATTENTION_DEFAULT_WINDOW = 7 * 86400
_INSTALLED_KEY = "admin.attention_installed_at"


def _seen_key(admin: str) -> str:
    return f"admin.attention_seen.{admin}"


def _ts(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def mark_attention_seen(store, admin: str, when: Optional[float] = None) -> float:
    ts = float(when if when is not None else time.time())
    store.set_setting(_seen_key(admin), f"{ts:.3f}")
    return ts


def attention_status(store, admin: str, now: Optional[float] = None) -> dict:
    """Grund + Anzahl fuer den Admin-Punkt. Keine sensiblen Felder."""
    from ..alerts import KIND_LABELS
    now = float(now if now is not None else time.time())
    since = _ts(store.get_setting(_seen_key(admin), ""), now - ATTENTION_DEFAULT_WINDOW)
    installed = _ts(store.get_setting(_INSTALLED_KEY, ""), now)
    reasons: list[dict] = []
    users = list(store.list_users())
    new_names = []
    for u in users:
        if not u["active"] or u["username"] == admin:
            continue
        created = _ts(u["created_at"])
        if created > since:
            new_names.append(u["username"])
            continue
        # Erst-Login eines schon laenger angelegten Kontos (nur Konten, die nach
        # Einfuehrung dieser Funktion angelegt wurden, sonst Fehlalarm bei Altkonten).
        first = _ts(store.get_setting(f"user.first_login.{u['username']}", ""))
        if first > since and created >= installed and first - created > 60:
            new_names.append(u["username"])
    if new_names:
        reasons.append({"kind": "new_users", "count": len(new_names),
                        "label": "Neue Benutzer", "users": new_names[:10]})
    for kind, n in store.alert_counts_since(ATTENTION_ALERT_KINDS, since).items():
        reasons.append({"kind": kind, "count": n, "label": KIND_LABELS.get(kind, kind)})
    locked = [u["username"] for u in users
              if not u["active"] and _ts(u["disabled_at"]) > since
              and (u["disabled_by"] or "") != admin]
    if locked:
        reasons.append({"kind": "accounts_locked", "count": len(locked),
                        "label": "Konten gesperrt", "users": locked[:10]})
    total = sum(r["count"] for r in reasons)
    return {"blink": total > 0, "count": total, "reasons": reasons, "since": since}


_TOKEN_IN_PATH = re.compile(r"(/invite/)([A-Za-z0-9_-]{6})[A-Za-z0-9_-]+")


class _RedactInviteToken(logging.Filter):
    """Kuerzt /invite/<token> im uvicorn-Access-Log auf 6 Zeichen."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            if isinstance(record.args, tuple) and record.args:
                record.args = tuple(
                    _TOKEN_IN_PATH.sub(r"\1\2…", a) if isinstance(a, str) else a
                    for a in record.args
                )
            if isinstance(record.msg, str) and "/invite/" in record.msg:
                record.msg = _TOKEN_IN_PATH.sub(r"\1\2…", record.msg)
        except Exception:  # noqa: BLE001
            pass
        return True


def install_log_redaction() -> None:
    for name in ("uvicorn.access", "uvicorn.error", "antbb.admin"):
        lg = logging.getLogger(name)
        if not any(isinstance(f, _RedactInviteToken) for f in lg.filters):
            lg.addFilter(_RedactInviteToken())


def kick_user(store, actor: str, username: str) -> Optional[str]:
    """Kicken & sperren. Kein Self-Kick, letzter aktiver Admin bleibt."""
    row = store.get_user(username)
    if not row:
        return "Benutzer nicht gefunden."
    actor_row = store.get_user(actor) if actor else None
    if username == actor or (actor_row is not None and actor_row["id"] == row["id"]):
        return "Du kannst dich nicht selbst kicken."
    if row["role"] == "admin" and row["active"] and store.count_active_admins() <= 1:
        return "Der letzte aktive Admin kann nicht gesperrt werden."
    store.set_user_disabled(username, True, by=actor)
    return None


# ---- Routen -----------------------------------------------------------------
def _act(store, request, kind: str, **kw) -> None:
    try:
        from . import activity
        activity.record(store, request, kind, **kw)
    except Exception:  # noqa: BLE001
        pass


def register(app: FastAPI, templates, store_getter: Callable[[], Any]) -> None:
    install_log_redaction()
    try:
        _st = store_getter()
        if not _st.get_setting(_INSTALLED_KEY, ""):
            _st.set_setting(_INSTALLED_KEY, f"{time.time():.3f}")
    except Exception:  # noqa: BLE001
        pass

    def _portal(request: Request, *, message: str = "", error: str = "",
                new_invite: Optional[dict] = None, status_code: int = 200):
        store = store_getter()
        user = _require_admin(request)
        users = [dict(u) for u in store.list_users()]
        invites = [_invite_dict(r) for r in store.list_invites()][:50]
        return templates.TemplateResponse(request, "admin_users.html", {
            "me": user.get("username"),
            "users": users,
            "invites": invites,
            "roles": list(webauth.ROLES),
            "message": message,
            "error": error,
            "new_invite": new_invite,
            "smtp": _smtp_configured(),
            "alert_users": store.open_alert_users(),
            "fmt_ts": lambda ts: time.strftime("%d.%m.%Y %H:%M", time.localtime(float(ts))) if ts else "–",
        }, status_code=status_code)

    @app.get("/admin", include_in_schema=False)
    def admin_root(request: Request):
        _require_admin(request)
        return RedirectResponse("/admin/users", status_code=303)

    @app.get("/admin/users", response_class=HTMLResponse)
    def admin_users(request: Request, message: str = "", error: str = ""):
        user = _require_admin(request)
        # Besuch der Benutzerverwaltung quittiert den Admin-Hinweis (Punkt).
        mark_attention_seen(store_getter(), user.get("username") or "")
        return _portal(request, message=message, error=error)

    @app.get("/api/admin/attention")
    def api_attention(request: Request):
        user = _require_admin(request)
        return attention_status(store_getter(), user.get("username") or "")

    @app.post("/api/admin/attention/seen")
    def api_attention_seen(request: Request):
        user = _require_admin(request)
        ts = mark_attention_seen(store_getter(), user.get("username") or "")
        return {"ok": True, "seen_at": ts}

    @app.post("/admin/attention/seen", include_in_schema=False)
    def admin_attention_seen(request: Request, next: str = Form("/admin/users")):
        user = _require_admin(request)
        from .. import webguard
        mark_attention_seen(store_getter(), user.get("username") or "")
        return RedirectResponse(webguard.safe_next(next), status_code=303)

    @app.post("/admin/users/invite", response_class=HTMLResponse)
    def admin_invite(request: Request, email: str = Form(""), username: str = Form(""),
                     role: str = Form("member"), days: int = Form(7),
                     confirm_admin: str = Form("off"), send_mail: str = Form("off")):
        user = _require_admin(request)
        try:
            inv = create_invite(store_getter(), created_by=user.get("username") or "admin",
                                role=role, email=email, username=username, days=days,
                                confirm_admin=(confirm_admin == "on"))
        except ValueError as exc:
            return _portal(request, error=str(exc), status_code=400)
        url = f"{_base_url(request)}/invite/{inv['token']}"
        inv["url"] = url
        inv["mailto"] = _mailto(inv["email"], url, inv["role"]) if inv["email"] else ""
        _act(store_getter(), request, "invite_created", detail=f"ref={inv['ref']} role={inv['role']}")
        msg = "Einladung erstellt. Der Link wird nur jetzt einmal vollständig angezeigt."
        if inv["email"] and send_mail == "on":
            _ok, note = _send_smtp(inv["email"], url, inv["role"])
            msg += " " + note
        return _portal(request, message=msg, new_invite=inv)

    @app.post("/admin/users/invites/{ref}/revoke", include_in_schema=False)
    def admin_revoke(request: Request, ref: str):
        _require_admin(request)
        store = store_getter()
        row = store.get_invite_by_ref(ref)
        if not row or not store.revoke_invite(row["token"]):
            return RedirectResponse("/admin/users?error=" + quote("Einladung nicht widerrufbar."), status_code=303)
        log.info("invite revoked ref=%s", ref)
        _act(store, request, "invite_revoked", detail=f"ref={ref}")
        return RedirectResponse("/admin/users?message=" + quote("Einladung widerrufen."), status_code=303)

    @app.post("/admin/users/{username}/role", include_in_schema=False)
    def admin_role(request: Request, username: str, role: str = Form(...)):
        user = _require_admin(request)
        err = change_user(store_getter(), user.get("username") or "", username, role=role)
        if err:
            return RedirectResponse("/admin/users?error=" + quote(err), status_code=303)
        return RedirectResponse("/admin/users?message=" + quote(f"Rolle von {username} gespeichert."), status_code=303)

    @app.post("/admin/users/{username}/active", include_in_schema=False)
    def admin_active(request: Request, username: str, active: str = Form("off")):
        user = _require_admin(request)
        flag = active == "on"
        err = change_user(store_getter(), user.get("username") or "", username, active=flag)
        if err:
            return RedirectResponse("/admin/users?error=" + quote(err), status_code=303)
        word = "aktiviert" if flag else "deaktiviert"
        return RedirectResponse("/admin/users?message=" + quote(f"{username} {word}."), status_code=303)

    # ---- JSON-API (admin-only) ----
    @app.get("/api/users")
    def api_users(request: Request):
        _require_admin(request)
        store = store_getter()
        return {
            "users": [
                {"username": u["username"], "role": u["role"], "active": bool(u["active"]),
                 "created_at": u["created_at"]} for u in store.list_users()
            ],
            "invites": [_invite_dict(r) for r in store.list_invites()],
            "roles": list(webauth.ROLES),
            "smtp": _smtp_configured(),
        }

    @app.post("/api/users/invite")
    async def api_invite(request: Request):
        user = _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        try:
            inv = create_invite(store_getter(), created_by=user.get("username") or "admin",
                                role=str(body.get("role") or "member"),
                                email=str(body.get("email") or ""),
                                username=str(body.get("username") or ""),
                                days=body.get("days") or 7,
                                confirm_admin=bool(body.get("confirm_admin")))
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        _act(store_getter(), request, "invite_created", detail=f"ref={inv['ref']} role={inv['role']}")
        url = f"{_base_url(request)}/invite/{inv['token']}"
        out = {"ok": True, "ref": inv["ref"], "role": inv["role"], "email": inv["email"],
               "username": inv["username"], "days": inv["days"], "url": url}
        if inv["email"]:
            out["mailto"] = _mailto(inv["email"], url, inv["role"])
            if body.get("send_mail"):
                out["mail_sent"], out["mail_note"] = _send_smtp(inv["email"], url, inv["role"])
        return out

    @app.post("/api/users/invites/{ref}/revoke")
    def api_revoke(request: Request, ref: str):
        _require_admin(request)
        store = store_getter()
        row = store.get_invite_by_ref(ref) or store.get_invite(ref)
        if not row or not store.revoke_invite(row["token"]):
            return JSONResponse({"error": "Einladung nicht widerrufbar."}, status_code=404)
        _act(store, request, "invite_revoked", detail=f"ref={row['ref']}")
        return {"ok": True, "ref": row["ref"], "status": "revoked"}

    @app.patch("/api/users/{username}")
    async def api_patch_user(request: Request, username: str):
        user = _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        role = body.get("role")
        active = body.get("active")
        err = change_user(store_getter(), user.get("username") or "", username,
                          role=str(role) if role is not None else None,
                          active=bool(active) if active is not None else None)
        if err:
            return JSONResponse({"error": err}, status_code=400)
        row = store_getter().get_user(username)
        return {"ok": True, "username": username, "role": row["role"], "active": bool(row["active"])}

    # ---- Einladung annehmen (oeffentlich) ----
    def _invite_page(request: Request, token: str, *, error: str = "", status_code: int = 200):
        row = store_getter().get_invite(token)
        valid = bool(row) and invite_status(row) == "pending"
        return templates.TemplateResponse(request, "invite.html", {
            "token": token if valid else "",
            "valid": valid,
            "role": row["role"] if valid else "",
            "fixed_username": (row["username"] if valid else "") or "",
            "email": (row["email"] if valid else "") or "",
            "error": error,
            "min_pw": MIN_PASSWORD,
        }, status_code=status_code if valid or error else 410)

    @app.get("/invite/{token}", response_class=HTMLResponse, include_in_schema=False)
    def invite_get(request: Request, token: str):
        return _invite_page(request, token)

    @app.post("/invite/{token}", include_in_schema=False)
    def invite_post(request: Request, token: str, username: str = Form(""),
                    password: str = Form(""), password_confirm: str = Form("")):
        from .. import webguard
        if not webguard.csrf_ok(request, via_bearer=False):
            return _invite_page(request, token, error="Anfrage von fremder Seite abgelehnt.", status_code=403)
        host = request.client.host if request.client else "unknown"
        key = f"invite|{host}"
        if webauth.login_rate_limited(key):
            return _invite_page(request, token, error="Zu viele Versuche. Bitte später erneut.", status_code=429)
        store = store_getter()
        row, err = accept_invite(store, token, username, password, password_confirm)
        if err:
            webauth.note_login_failure(key)
            if store.get_invite(token) is None:
                from ..alerts import raise_alert
                raise_alert(store, "invite_invalid", ip=host, path="/invite/…")
            return _invite_page(request, token, error=err, status_code=400)
        webauth.clear_login_failures(key)
        _act(store, request, "invite_accepted", username=row["username"], role=row["role"])
        session = webauth.start_session(store, row)
        response = RedirectResponse("/", status_code=303)
        webguard._set_session_cookie(response, request, session)
        return response

    # ---- Kick & Sperre / Entsperren / 2FA-Reset (admin-only) ----
    def _audit(store, kind: str, request: Request, target: str, severity: str = "info"):
        from ..alerts import raise_alert
        actor = _user(request).get("username") or ""
        raise_alert(store, kind, username=target, ip=(request.client.host if request.client else ""),
                    path=request.url.path, detail=f"by={actor}", severity=severity)
        log.info("audit %s user=%s by=%s", kind, target, actor)

    @app.post("/admin/users/{username}/kick", include_in_schema=False)
    def admin_kick(request: Request, username: str):
        user = _require_admin(request)
        err = kick_user(store_getter(), user.get("username") or "", username)
        if err:
            return RedirectResponse("/admin/users?error=" + quote(err), status_code=303)
        _audit(store_getter(), "user_kicked", request, username, severity="warn")
        return RedirectResponse("/admin/users?message=" + quote(f"{username} gekickt & gesperrt."), status_code=303)

    @app.post("/admin/users/{username}/unlock", include_in_schema=False)
    def admin_unlock(request: Request, username: str):
        _require_admin(request)
        store = store_getter()
        if not store.get_user(username):
            return RedirectResponse("/admin/users?error=" + quote("Benutzer nicht gefunden."), status_code=303)
        store.set_user_disabled(username, False)
        _audit(store, "user_unlocked", request, username)
        return RedirectResponse("/admin/users?message=" + quote(f"{username} entsperrt."), status_code=303)

    @app.post("/admin/users/{username}/reset-2fa", include_in_schema=False)
    def admin_reset_2fa(request: Request, username: str):
        _require_admin(request)
        store = store_getter()
        if not store.get_user(username):
            return RedirectResponse("/admin/users?error=" + quote("Benutzer nicht gefunden."), status_code=303)
        store.disable_totp(username)
        log.info("2fa reset user=%s by=%s", username, _user(request).get("username"))
        return RedirectResponse("/admin/users?message=" + quote(f"2FA von {username} zurückgesetzt."), status_code=303)

    # ---- Alarme (nur Web-UI + optional ntfy; admin-only) ----
    @app.get("/admin/alerts", response_class=HTMLResponse)
    def admin_alerts(request: Request, message: str = ""):
        _require_admin(request)
        from ..alerts import KIND_LABELS, ntfy_configured
        store = store_getter()
        return templates.TemplateResponse(request, "admin_alerts.html", {
            "alerts": [dict(a) for a in store.list_alerts()],
            "labels": KIND_LABELS, "message": message, "ntfy": ntfy_configured(),
            "fmt_ts": lambda ts: time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(float(ts))) if ts else "–",
        })

    @app.get("/api/admin/alerts/count")
    def api_alert_count(request: Request):
        _require_admin(request)
        store = store_getter()
        return {"open": store.count_open_alerts(), "users": store.open_alert_users()}

    @app.post("/admin/alerts/ack", include_in_schema=False)
    def admin_alerts_ack(request: Request, next: str = Form("/admin/alerts")):
        user = _require_admin(request)
        from .. import webguard
        n = store_getter().ack_alerts(user.get("username") or "admin")
        dest = webguard.safe_next(next)
        sep = "&" if "?" in dest else "?"
        if dest.startswith("/admin/alerts"):
            dest = f"/admin/alerts{sep}message=" + quote(f"{n} Alarm(e) quittiert.")
        return RedirectResponse(dest, status_code=303)

    @app.post("/admin/alerts/{alert_id}/ack", include_in_schema=False)
    def admin_alert_ack_one(request: Request, alert_id: int):
        user = _require_admin(request)
        store_getter().ack_alerts(user.get("username") or "admin", alert_id=alert_id)
        return RedirectResponse("/admin/alerts?message=" + quote("Alarm quittiert."), status_code=303)

    @app.post("/api/admin/alerts/ack")
    def api_alerts_ack(request: Request):
        user = _require_admin(request)
        return {"ok": True, "acked": store_getter().ack_alerts(user.get("username") or "admin")}

    # ---- Wer bin ich? (fuer die statische Landing, nur mit Session) ----
    @app.get("/api/me")
    def api_me(request: Request):
        user = _user(request)
        name = user.get("username") or ""
        if not name:
            return JSONResponse({"error": "Authentication required."}, status_code=401)
        role = (user.get("role") or "").strip().lower()
        return {"username": name, "role": role, "is_admin": webauth.is_admin(role)}

    # ---- Profil: 2FA (jede Rolle, eigenes Konto) ----
    def _profile(request: Request, *, message: str = "", error: str = "",
                 recovery_codes: Optional[list] = None, status_code: int = 200,
                 pw_message: str = "", pw_error: str = ""):
        from .. import hosted
        from .. import totp as _totp
        user = _user(request)
        if not user.get("username"):
            raise HTTPException(401, "Anmeldung erforderlich.")
        row = store_getter().get_user(user["username"])
        if not row:
            raise HTTPException(404, "Benutzer nicht gefunden.")
        pending = _totp.decrypt(row["totp_pending_enc"] or "") if not row["totp_enabled"] else None
        try:
            import json as _json
            rc_left = len(_json.loads(row["recovery_hashes"] or "[]"))
        except Exception:
            rc_left = 0
        role = (row["role"] or "").strip().lower()
        return templates.TemplateResponse(request, "profile_2fa.html", {
            "me": row["username"],
            "role": role,
            "role_is_admin": webauth.is_admin(role),
            "can_change_pw": not hosted.is_guest(role),
            "pw_min": webauth.PASSWORD_MIN_LEN,
            "pw_message": pw_message, "pw_error": pw_error,
            "enabled": bool(row["totp_enabled"]),
            "pending_secret": pending or "",
            "pending_secret_grouped": " ".join((pending or "")[i:i + 4] for i in range(0, len(pending or ""), 4)),
            "otpauth": _totp.otpauth_uri(pending, row["username"]) if pending else "",
            "rc_left": rc_left,
            "recovery_codes": recovery_codes or [],
            "message": message, "error": error,
        }, status_code=status_code)

    @app.get("/profile", response_class=HTMLResponse, include_in_schema=False)
    def profile_root(request: Request):
        return _profile(request)

    @app.post("/profile/password", response_class=HTMLResponse, include_in_schema=False)
    def profile_password(request: Request, current_password: str = Form(""),
                         new_password: str = Form(""), new_password_confirm: str = Form("")):
        from .. import hosted, webguard
        from ..i18n import t
        user = _user(request)
        name = user.get("username") or ""
        if not name:
            raise HTTPException(401, "Anmeldung erforderlich.")
        if not webguard.csrf_ok(request, via_bearer=False):
            return _profile(request, pw_error=t("profile.pw.err_csrf"), status_code=403)
        if hosted.is_guest(user.get("role")):
            return _profile(request, pw_error=t("profile.pw.err_guest"), status_code=403)
        key = f"pwchange|{name.lower()}"
        if webauth.login_rate_limited(key):
            return _profile(request, pw_error=t("profile.pw.err_rate"), status_code=429)
        store = store_getter()
        err = webauth.change_own_password(store, name, current_password,
                                          new_password, new_password_confirm)
        if err:
            if err == "profile.pw.err_current":
                webauth.note_login_failure(key)
            log.info("password change rejected user=%s reason=%s", name, err.rsplit(".", 1)[-1])
            return _profile(request, pw_error=t(err, n=webauth.PASSWORD_MIN_LEN), status_code=400)
        webauth.clear_login_failures(key)
        # Alle Sessions des Benutzers beenden und die aktuelle neu ausstellen.
        old_token = request.cookies.get(webauth.COOKIE_NAME) or ""
        removed = store.delete_user_sessions(name)
        row = store.get_user(name)
        new_token = webauth.start_session(store, row)
        _act(store, request, "password_changed", detail="andere Sitzungen beendet")
        log.info("password changed user=%s sessions_revoked=%d", name,
                 max(0, removed - (1 if old_token else 0)))
        response = _profile(request, pw_message=t("profile.pw.ok"))
        webguard._set_session_cookie(response, request, new_token)
        return response

    @app.get("/profile/2fa", response_class=HTMLResponse)
    def profile_2fa(request: Request):
        return _profile(request)

    @app.post("/profile/2fa/setup", response_class=HTMLResponse)
    def profile_2fa_setup(request: Request):
        from .. import totp as _totp
        user = _user(request)
        store = store_getter()
        row = store.get_user(user.get("username") or "")
        if not row:
            raise HTTPException(401, "Anmeldung erforderlich.")
        if row["totp_enabled"]:
            return _profile(request, error="2FA ist bereits aktiv.")
        store.set_totp_pending(row["username"], _totp.encrypt(_totp.new_secret()))
        return _profile(request)

    @app.post("/profile/2fa/cancel", response_class=HTMLResponse)
    def profile_2fa_cancel(request: Request):
        user = _user(request)
        store_getter().set_totp_pending(user.get("username") or "", None)
        return _profile(request, message="Einrichtung abgebrochen.")

    @app.post("/profile/2fa/confirm", response_class=HTMLResponse)
    def profile_2fa_confirm(request: Request, code: str = Form("")):
        import json as _json
        from .. import totp as _totp
        user = _user(request)
        store = store_getter()
        row = store.get_user(user.get("username") or "")
        if not row:
            raise HTTPException(401, "Anmeldung erforderlich.")
        key = f"2fa-setup|{row['username'].lower()}"
        if webauth.login_rate_limited(key):
            return _profile(request, error="Zu viele Versuche. Bitte später erneut.", status_code=429)
        secret = _totp.decrypt(row["totp_pending_enc"] or "")
        if not secret:
            return _profile(request, error="Keine Einrichtung offen.", status_code=400)
        step = _totp.verify(secret, code)
        if step is None:
            webauth.note_login_failure(key)
            return _profile(request, error="Code ist falsch. Uhrzeit des Geräts prüfen.", status_code=400)
        codes = _totp.new_recovery_codes(8)
        store.enable_totp(row["username"], _totp.encrypt(secret), step,
                          _json.dumps([_totp.hash_recovery(c) for c in codes]))
        webauth.clear_login_failures(key)
        log.info("2fa enabled user=%s", row["username"])
        _act(store, request, "2fa_enabled")
        return _profile(request, message="2FA ist jetzt aktiv.", recovery_codes=codes)

    @app.post("/profile/2fa/disable", response_class=HTMLResponse)
    def profile_2fa_disable(request: Request, code: str = Form("")):
        user = _user(request)
        store = store_getter()
        name = user.get("username") or ""
        key = f"2fa|{name.lower()}"
        if webauth.login_rate_limited(key):
            return _profile(request, error="Zu viele Versuche. Bitte später erneut.", status_code=429)
        if not webauth.verify_second_factor(store, name, code):
            webauth.note_login_failure(key)
            return _profile(request, error="Code ist falsch oder wurde bereits verwendet.", status_code=400)
        store.disable_totp(name)
        log.info("2fa disabled user=%s", name)
        _act(store, request, "2fa_disabled")
        return _profile(request, message="2FA wurde deaktiviert.")

