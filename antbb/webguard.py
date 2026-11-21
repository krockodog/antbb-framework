"""Login wall in front of the web UI and API.

Every route except the health check requires a session. State-changing
requests that ride the session cookie must come from the same origin
(or present the CSRF token / a Bearer token). The official launcher
refuses to start when no admin credential is configured; a process that
is reached without one answers 503 instead of serving the console.
"""
from __future__ import annotations

import hmac
import re
import os
import secrets
import sys
from html import escape
from typing import Callable, Optional
from urllib.parse import quote, urlparse

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from . import webauth

_STORE = None
_GETTER: Optional[Callable] = None
_HEALTH_QUEENS = {"red", "blue", "yellow"}
_UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def default_store():
    global _STORE
    if _STORE is None:
        from .store import Store
        _STORE = Store()
    return _STORE


def _store_getter() -> Callable:
    return _GETTER or default_store


def _server_host(scope) -> str:
    server = scope.get("server") if scope is not None else None
    # uvicorn gives a tuple. Starlette's TestClient gives a list.
    if isinstance(server, (tuple, list)) and server:
        return str(server[0] or "")
    return ""


def _wants_json(request: Request) -> bool:
    path = request.url.path
    if path.startswith("/api") or path.startswith("/ws"):
        return True
    accept = (request.headers.get("accept") or "").lower()
    return "application/json" in accept and "text/html" not in accept


def _public(path: str, method: str) -> bool:
    if method in {"GET", "HEAD"} and path in {"/api/health", "/healthz"}:
        return True
    if method in {"GET", "HEAD"} and path.startswith("/api/health/"):
        queen = path.removeprefix("/api/health/").strip("/")
        return queen in _HEALTH_QUEENS and "/" not in queen
    if method in {"GET", "HEAD"}:
        from . import hosted
        if hosted.enabled() and hosted.login_asset(path):
            return True
    if path in {"/login", "/login/2fa"} and method in {"GET", "HEAD", "POST"}:
        return True
    if path == "/api/login/2fa" and method == "POST":
        return True
    # Einladung annehmen: oeffentlich wie /login. Das Token ist das Geheimnis;
    # Handler prueft Gueltigkeit, CSRF (Origin) und Rate-Limit selbst.
    if method in {"GET", "HEAD", "POST"} and _INVITE_PATH.match(path):
        return True
    if path == "/api/login" and method == "POST":
        return True
    return False


def _mode(request: Request) -> str:
    """auth | off | unconfigured."""
    if webauth.auth_enabled():
        return "auth"
    from . import hosted
    if hosted.enabled():
        return "unconfigured"
    host = _server_host(request.scope)
    if host in {"testserver", "testclient"} or os.environ.get("ANTBB_TESTING", "").strip() in {
        "1", "true", "yes", "on",
    }:
        return "off"
    return "unconfigured"


def cookie_secure(request: Request) -> bool:
    from . import hosted
    if hosted.enabled():
        return True
    if os.environ.get("ANTBB_COOKIE_SECURE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return True
    if request.url.scheme == "https":
        return True
    if os.environ.get("ANTBB_TRUST_PROXY", "").strip().lower() in {"1", "true", "yes", "on"}:
        proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
        return proto == "https"
    return False


def _origin_matches(value: str, request: Request) -> bool:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    expected = request.url.netloc
    # Browsers send the page origin. Trust the Host header only as a fallback
    # when the ASGI server rewrote the URL (test client).
    host_header = request.headers.get("host") or ""
    return parsed.netloc == expected or (host_header and parsed.netloc == host_header)


def csrf_ok(request: Request, *, via_bearer: bool) -> bool:
    """Browser CSRF check for cookie-authenticated unsafe methods.

    A Bearer token is not sent automatically by browsers, so it skips this.
    A cross-site browser POST always carries Origin and/or Sec-Fetch-Site.
    Non-browser clients that omit both may send X-CSRF-Token instead.
    """
    if via_bearer:
        return True
    fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
    if fetch_site == "cross-site":
        return False
    origin = request.headers.get("origin")
    if origin:
        return _origin_matches(origin, request)
    referer = request.headers.get("referer")
    if referer:
        return _origin_matches(referer, request)
    token = request.headers.get("x-csrf-token") or ""
    cookie = request.cookies.get(webauth.CSRF_COOKIE) or ""
    if token or cookie:
        return bool(token and cookie and hmac.compare_digest(token, cookie))
    return True


def _client_key(request: Request, username: str) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{host}|{(username or '').strip().lower()}"


_INVITE_PATH = re.compile(r"^/invite/[A-Za-z0-9_-]{16,128}$")
# Benutzerverwaltung + Einladungen: ausschliesslich admin (member -> 403).
_ADMIN_ONLY = re.compile(
    r"^/(admin|api/admin|api/users|exports|api/exports"
    # Leck-Audit 2026-11-11: Modell-/Provider-Konfiguration, Server-Software-
    # Inventar, Plugin-/Remote-Tunnel-Interna sind reine Admin-Sicht.
    r"|providers|api/llm|api/edition|api/blue/softwarescan|api/plugins|api/remote)(?:/|$)"
)

# Fuer Nicht-Admins werden interne Serverpfade in JSON/HTML-Antworten
# neutralisiert (Leck-Audit). Admins sehen alles unveraendert.
_INTERNAL_PATH_RX = re.compile(
    rb"(?:/opt/antbb[\w.-]*|/home/ubuntu|/usr/(?:local/)?(?:s?bin|lib(?:exec)?|share)|/etc/ssh|/var/lib/docker)"
    rb"(?:/[\w.@+-]+)*"
)
_REDACT_TYPES = ("application/json", "text/html")
_REDACT_MAX = 8 * 1024 * 1024


# Schreibaktionen, die auch member (Operator) NICHT darf: Modus-Policy,
# Papierkorb, Blue-Remediation, Fernzugriff. Gaeste sind ohnehin gesperrt.
_ADMIN_ONLY_WRITES = tuple(re.compile(p) for p in (
    r"^/target/\d+/(mode|archive|restore)$",
    r"^/api/targets/\d+/mode$",
    r"^/api/blue/findings/\d+/apply$",
    r"^/api/blue/findings/\d+/remediate-recheck$",
    r"^/remote/set$",
    r"^/api/remote(?:/|$)",
))


def _needs_admin(path: str, method: str) -> bool:
    if _ADMIN_ONLY.match(path or ""):
        return True
    if method in _UNSAFE and any(rx.match(path or "") for rx in _ADMIN_ONLY_WRITES):
        return True
    if not path.startswith("/api/brain"):
        return False
    if method == "DELETE":
        return True
    if method == "POST" and "/reset" in path:
        return True
    return False


# Pro-User-Trennung: Pfade mit Target-ID bzw. Report-ID.
_TARGET_ID_PATH = re.compile(r"^/(?:api/targets|target|api/brain)/(\d+)(?:/|$)")
_REPORT_ID_PATH = re.compile(r"^/report/(\d+)(?:/|$)")
_WLAN_PAGE = re.compile(r"^/wlan(?:/|$)")
_WLAN_API = re.compile(r"^/api/wlan(?:/|$)")


def _role_gate(store, row, path: str, method: str):
    """(alarm_kind, meldung) wenn verweigert, sonst None.

    * member/member_plus sehen nur eigene Ziele (owner_user). Alt-Ziele ohne
      Owner und fremde Ziele -> 403. admin sieht alles. Gaeste behalten den
      bisherigen Lesezugriff auf die vom Admin bereitgestellten Ziele.
    * Hosted-WLAN-Kanal: nur admin + member_plus (Seite + Schreib-API).
    """
    role = (row["role"] or "").strip().lower()
    if role == "admin":
        return None
    from . import hosted
    if hosted.enabled() and not webauth.can_wlan(role):
        if _WLAN_PAGE.match(path) or (method in _UNSAFE and _WLAN_API.match(path)):
            return ("wlan_denied", "Der WLAN-Kanal ist admin und member_plus vorbehalten.")
    if role in {"member", "member_plus"}:
        tid = None
        m = _TARGET_ID_PATH.match(path)
        if m:
            tid = int(m.group(1))
        else:
            m = _REPORT_ID_PATH.match(path)
            if m:
                tid = store.report_target_id(int(m.group(1)))
                if tid is None:
                    return ("owner_denied", "Kein Zugriff auf diesen Bericht.")
        if tid is not None:
            owner = store.target_owner(tid)
            if owner != row["username"]:
                return ("owner_denied", "Kein Zugriff: dieses Ziel gehört einem anderen Benutzer.")
    return None


# Kein Aktivitaets-Eintrag fuer Assets und Polling-Endpunkte.
_NOLOG_PREFIX = ("/static/", "/_next/", "/api/admin/attention", "/api/admin/alerts/count",
                 "/api/admin/activity/live", "/favicon")
_NOLOG_PATHS = frozenset({"/api/me", "/api/meta", "/healthz", "/api/health"})

_VIEWER_POST_OK = frozenset({"/login", "/logout", "/api/login", "/api/logout"})


def _guest_role(role: str) -> bool:
    from . import hosted
    return hosted.is_guest(role)


async def _peek_body(request: Request) -> dict:
    """Read JSON or urlencoded form once; Starlette caches the raw body."""
    ctype = (request.headers.get("content-type") or "").lower()
    if "multipart/form-data" in ctype:
        return {}
    try:
        raw = await request.body()
    except Exception:
        return {}
    if not raw:
        return {}
    if "application/json" in ctype or (raw[:1] in (b"{", b"[") and "form" not in ctype):
        try:
            import json
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    if "application/x-www-form-urlencoded" in ctype:
        from urllib.parse import parse_qs
        parsed = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        return {k: (v[0] if v else "") for k, v in parsed.items()}
    return {}


def _viewer_write_blocked(role: str, path: str, method: str) -> bool:
    """Deprecated name kept for callers. Use guest allowlist (deny-by-default)."""
    from . import hosted

    if not hosted.enabled() or not hosted.is_guest(role):
        return False
    if method in {"GET", "HEAD", "OPTIONS"}:
        return False
    return not hosted.guest_write_allowed(path, method)


def safe_next(target: str) -> str:
    value = target or "/"
    if not value.startswith("/") or value.startswith("//") or value.startswith("/\\"):
        return "/"
    if "\\" in value or "://" in value:
        return "/"
    return value


def _samesite() -> str:
    from . import hosted
    return "strict" if hosted.enabled() else "lax"


def _set_session_cookie(response, request: Request, token: str) -> None:
    response.set_cookie(
        webauth.COOKIE_NAME,
        token,
        httponly=True,
        samesite=_samesite(),
        secure=cookie_secure(request),
        max_age=86400 * 7,
        path="/",
    )
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(
        webauth.CSRF_COOKIE,
        csrf,
        httponly=False,
        samesite=_samesite(),
        secure=cookie_secure(request),
        max_age=86400 * 7,
        path="/",
    )


def _session(store, request: Request):
    token = request.cookies.get(webauth.COOKIE_NAME)
    via_bearer = False
    if not token:
        header = request.headers.get("authorization") or ""
        if header.lower().startswith("bearer "):
            token = header[7:].strip()
            via_bearer = True
    if not token:
        return None, False
    try:
        row = webauth.session_user(store, token)
        if row is not None:
            # Revocation-Check bei jedem Request: gesperrte/inaktive Benutzer
            # verlieren ihre Session sofort (Kick).
            user = store.get_user(row["username"])
            if not user or not user["active"]:
                store.delete_session(token)
                return None, via_bearer
            # Inaktivitaets-Timeout (Default 12 h, ANTBB_SESSION_IDLE_SECONDS);
            # absolute Laufzeit bleibt 7 Tage (store.create_session).
            from .web import activity as _act
            last = _act.session_last_seen(store, token)
            import time as _time
            if last is not None and _time.time() - last > _idle_timeout():
                store.delete_session(token)
                return None, via_bearer
            _act.touch_session(store, request, token, row["username"])
    except Exception:
        return None, via_bearer
    return row, via_bearer


def _login_html(error: str, nxt: str) -> str:
    safe_error = escape(error or "", quote=True)
    safe_target = escape(nxt or "/", quote=True)
    message = f"<p class='err'>{safe_error}</p>" if safe_error else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in · antbb</title>
  <style>
    body {{ font: 16px/1.4 system-ui, sans-serif; background:#0e1116; color:#e8eef7; }}
    main {{ max-width: 26rem; margin: 4rem auto; padding: 1.5rem; background:#171c24; border-radius: 12px; }}
    label {{ display:block; margin: .8rem 0; }}
    input {{ width:100%; padding:.5rem; box-sizing:border-box; }}
    button {{ margin-top:.6rem; padding:.5rem 1rem; }}
    .err {{ color:#ffb4b4; }}
    p.note {{ color:#9aabbe; font-size:.9rem; }}
  </style>
</head>
<body>
<main>
  <h1>Sign in</h1>
  {message}
  <form method="post" action="/login">
    <input type="hidden" name="next" value="{safe_target}">
    <label>Username <input name="username" autocomplete="username" required autofocus></label>
    <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
    <button type="submit">Sign in</button>
  </form>
  <p class="note">Authorized scope only. This console has no default password.</p>
</main>
</body>
</html>
"""


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _alert(store, kind: str, request: Request, *, username=None, detail: str = "",
           severity: str = "warn") -> None:
    try:
        from .alerts import raise_alert
        raise_alert(store, kind, username=username, ip=_client_ip(request),
                    path=request.url.path, detail=detail, severity=severity)
    except Exception:
        pass


def _activity(store, request: Request, kind: str, **kw) -> None:
    try:
        from .web import activity as _act
        _act.record(store, request, kind, **kw)
    except Exception:  # noqa: BLE001
        pass


def _idle_timeout() -> float:
    try:
        return max(300.0, float(os.environ.get("ANTBB_SESSION_IDLE_SECONDS", str(12 * 3600))))
    except ValueError:
        return 12 * 3600.0


def _server_error_alert(store, request: Request, username, status: int = 500) -> None:
    """5xx/Exception als Alarm 'server_error' (dedupliziert je Pfad, 5 min).
    Speist den Admin-Hinweis (Punkt). Fehler hier brechen nie den Request."""
    try:
        _alert(store, "server_error", request, username=username,
               detail=f"status={status}")
    except Exception:  # noqa: BLE001
        pass


def _complete_2fa(store, request: Request, pending: str, code: str):
    """Zweiter Schritt. Fehlversuchs-Limit pro Pending-Token + pro Benutzer."""
    from .i18n import t
    is_api = request.url.path.startswith("/api") or _wants_json(request)

    def _fail(status: int, msg: str, keep: bool = True):
        if is_api:
            return JSONResponse({"error": msg}, status_code=status)
        dest = "/login/2fa" if keep else "/login"
        return RedirectResponse(url=f"{dest}?error={quote(msg)}", status_code=303)

    if request.headers.get("origin") and not csrf_ok(request, via_bearer=False):
        return _fail(403, t("login.error_csrf"), keep=False)
    entry = webauth.get_pending_2fa(pending)
    if not entry:
        return _fail(401, "Anmeldung abgelaufen. Bitte erneut anmelden.", keep=False)
    username = entry["username"]
    ukey = f"2fa|{username.lower()}"
    if webauth.login_rate_limited(ukey):
        webauth.drop_pending_2fa(pending)
        _alert(store, "login_bruteforce_2fa", request, username=username, severity="high")
        _activity(store, request, "2fa_limited", username=username, status=429)
        return _fail(429, t("login.error_limited"), keep=False)
    method = webauth.verify_second_factor(store, username, code)
    if not method:
        _activity(store, request, "2fa_failed", username=username, status=401)
        entry["fails"] += 1
        webauth.note_login_failure(ukey)
        if entry["fails"] >= webauth.PENDING_MAX_FAILS:
            webauth.drop_pending_2fa(pending)
            _alert(store, "login_bruteforce_2fa", request, username=username, severity="high")
            return _fail(429, "Zu viele falsche Codes. Bitte erneut anmelden.", keep=False)
        return _fail(401, "Code ist falsch oder wurde bereits verwendet.")
    webauth.drop_pending_2fa(pending)
    webauth.clear_login_failures(ukey)
    row = store.get_user(username)
    if not row or not row["active"]:
        return _fail(401, t("login.error_bad"), keep=False)
    token = webauth.start_session(store, row)
    _activity(store, request, "2fa_ok", username=row["username"], role=row["role"], detail=method)
    if is_api:
        response = JSONResponse({"ok": True, "username": row["username"],
                                 "role": row["role"], "token": token, "second_factor": method})
    else:
        response = RedirectResponse(url=safe_next(entry.get("next") or "/"), status_code=303)
    response.delete_cookie(webauth.PENDING_COOKIE, path="/login")
    _set_session_cookie(response, request, token)
    return response


def _fail_login(request: Request, *, status: int, detail: str, nxt: str = "/"):
    if _wants_json(request) or request.url.path.startswith("/api"):
        return JSONResponse({"error": detail}, status_code=status)
    return RedirectResponse(
        url=f"/login?error={quote(detail)}&next={quote(safe_next(nxt))}",
        status_code=303,
    )


def _attempt_login(store, request: Request, username: str, password: str, nxt: str):
    from .i18n import t
    if request.headers.get("origin") and not csrf_ok(request, via_bearer=False):
        return _fail_login(request, status=403, detail=t("login.error_csrf"), nxt=nxt)
    key = _client_key(request, username)
    limited = webauth.login_rate_limited(key)
    from . import hosted
    # Hosted mode also counts failures per username across all client IPs,
    # so rotating source addresses does not reset the budget.
    global_key = f"*|{(username or '').strip().lower()}" if hosted.enabled() else None
    if global_key and webauth.login_rate_limited(global_key, scale=3):
        limited = True
    row = webauth.authenticate(store, username, password)
    if limited:
        _alert(store, "login_limited", request, username=None,
               detail=f"user={(username or '')[:64]}", severity="high")
        _activity(store, request, "login_limited", username=(username or "")[:64], status=429)
        return _fail_login(
            request, status=429,
            detail=t("login.error_limited"), nxt=nxt,
        )
    if not row:
        webauth.note_login_failure(key)
        if global_key:
            webauth.note_login_failure(global_key)
        _activity(store, request, "login_failed", username=(username or "")[:64], status=401)
        return _fail_login(
            request, status=401,
            detail=t("login.error_bad"), nxt=nxt,
        )
    webauth.clear_login_failures(key)
    if global_key:
        webauth.clear_login_failures(global_key)
    dest = safe_next(nxt)
    if webauth.totp_enabled(row):
        _activity(store, request, "login_password_ok_2fa_pending", username=row["username"], role=row["role"])
        # Zweistufig: Passwort ok -> kurzlebiges Pending-Token -> /login/2fa.
        pending = webauth.start_pending_2fa(row["username"], dest)
        if request.url.path.startswith("/api") or _wants_json(request):
            response = JSONResponse({"ok": False, "2fa_required": True, "pending": pending})
        else:
            response = RedirectResponse(url=f"/login/2fa?next={quote(dest)}", status_code=303)
        response.set_cookie(webauth.PENDING_COOKIE, pending, httponly=True,
                            samesite=_samesite(), secure=cookie_secure(request),
                            max_age=int(webauth.PENDING_TTL), path="/login")
        return response
    token = webauth.start_session(store, row)
    _activity(store, request, "login_ok", username=row["username"], role=row["role"], status=200)
    if request.url.path.startswith("/api") or _wants_json(request):
        response = JSONResponse({
            "ok": True,
            "username": row["username"],
            "role": row["role"],
            "token": token,
        })
    else:
        response = RedirectResponse(url=dest, status_code=303)
    _set_session_cookie(response, request, token)
    return response


def install(app: FastAPI, store_getter: Optional[Callable] = None) -> None:
    global _GETTER
    if getattr(app.state, "antbb_guard", False):
        return
    app.state.antbb_guard = True
    getter = store_getter or default_store
    _GETTER = getter

    @app.on_event("startup")
    def _guard_startup() -> None:
        from .netbind import argv_host, assert_runtime_safe

        serving = os.environ.get("ANTBB_SERVE") == "1" or any(
            "uvicorn" in part for part in sys.argv
        )
        testing = os.environ.get("ANTBB_TESTING", "").strip().lower() in {"1", "true", "yes", "on"}
        if serving and not testing:
            assert_runtime_safe(argv_host())
        try:
            created = webauth.bootstrap_admin(getter())
        except ValueError as exc:
            if serving and not testing:
                raise SystemExit(str(exc)) from exc
            raise
        if created and serving:
            print(f"[antbb.auth] admin '{created}' synced from the environment.", flush=True)

    @app.middleware("http")
    async def _redact_internal(request: Request, call_next):
        """Interne Pfade fuer Nicht-Admins ausblenden (nicht-destruktiv,
        nur die Auslieferung; Daten bleiben unveraendert)."""
        response = await call_next(request)
        user = getattr(request.state, "user", None) or {}
        if user.get("role") == "admin":
            return response
        ctype = (response.headers.get("content-type") or "").lower()
        if not ctype.startswith(_REDACT_TYPES):
            return response
        try:
            clen = int(response.headers.get("content-length") or 0)
        except ValueError:
            clen = 0
        if clen > _REDACT_MAX:
            return response
        body = b""
        async for chunk in response.body_iterator:
            body += chunk if isinstance(chunk, bytes) else chunk.encode()
        new = _INTERNAL_PATH_RX.sub(b"[intern]", body)
        out = Response(new, status_code=response.status_code, background=response.background)
        out.raw_headers = [(k, v) for k, v in response.raw_headers if k.lower() != b"content-length"]
        out.raw_headers.append((b"content-length", str(len(new)).encode()))
        return out

    @app.middleware("http")
    async def _language(request: Request, call_next):
        from .i18n import activate_request, stamp_lang_cookie

        activate_request(request)
        response = await call_next(request)
        return stamp_lang_cookie(response, request)

    @app.middleware("http")
    async def _guard(request: Request, call_next):
        from .netbind import bind_violation

        violation = bind_violation(_server_host(request.scope))
        if violation:
            return JSONResponse({"error": violation}, status_code=503)

        path = request.url.path
        method = request.method.upper()
        if _public(path, method):
            return await call_next(request)

        mode = _mode(request)
        if mode == "off":
            return await call_next(request)
        if mode == "unconfigured":
            return JSONResponse(
                {"error": (
                    "Refusing to serve: set ANTBB_ADMIN_PASSWORD_HASH "
                    "(or ANTBB_ADMIN_PASSWORD). There is no default password."
                )},
                status_code=503,
            )

        try:
            store = getter()
        except Exception:
            return JSONResponse({"error": "Authentication store is unavailable."}, status_code=503)
        row, via_bearer = _session(store, request)
        if not row:
            if _wants_json(request):
                return JSONResponse({"error": "Authentication required."}, status_code=401)
            nxt = quote(safe_next(path if path else "/"))
            return RedirectResponse(url=f"/login?next={nxt}", status_code=303)
        # GET /logout is state-changing. Modern browsers send Sec-Fetch-Site.
        if (method in _UNSAFE or path == "/logout") and not csrf_ok(request, via_bearer=via_bearer):
            return JSONResponse({"error": "Cross-site request was rejected."}, status_code=403)
        if _needs_admin(path, method) and row["role"] != "admin":
            if _ADMIN_ONLY.match(path or ""):
                _alert(store, "admin_denied", request, username=row["username"])
            return JSONResponse(
                {"error": "Only an admin may run this action."},
                status_code=403,
            )
        denied = _role_gate(store, row, path, method)
        if denied:
            kind, msg = denied
            _alert(store, kind, request, username=row["username"])
            if _wants_json(request):
                return JSONResponse({"error": msg}, status_code=403)
            return HTMLResponse(f"<!doctype html><meta charset=utf-8><p>{escape(msg)}</p>"
                                "<p><a href='/'>Zurück</a></p>", status_code=403)
        from . import hosted as _hosted
        rate_entered = False
        rate_user = ""
        hold_parallel = False
        if _hosted.enabled() and _hosted.is_guest(row["role"]) and method in _UNSAFE:
            if not _hosted.guest_write_allowed(path, method):
                return JSONResponse(
                    {"error": (
                        "Diese Aktion ist dem Admin vorbehalten. "
                        "Der Gast darf das Programm, Scope, Oversight für "
                        "Offensiv-Läufe und Systemänderungen nicht verändern."
                    )},
                    status_code=403,
                )
            body = await _peek_body(request)
            denied = _hosted.guest_payload_denied(path, body)
            if denied:
                return JSONResponse({"error": denied}, status_code=403)
            cl = request.headers.get("content-length") or ""
            if "upload" in path or path.endswith("/classify") or path == "/api/classify":
                try:
                    if cl and int(cl) > _hosted.guest_upload_limit_bytes():
                        return JSONResponse(
                            {"error": (
                                "Gast-Upload zu groß (max. "
                                f"{_hosted.guest_upload_limit_bytes() // (1024 * 1024)} MB)."
                            )},
                            status_code=413,
                        )
                except ValueError:
                    pass
            if _hosted.guest_is_run_start(path, method):
                err = _hosted.guest_rate_enter(row["username"] or _hosted.GUEST_ACTOR)
                if err:
                    return JSONResponse({"error": err}, status_code=429)
                rate_entered = True
                rate_user = row["username"] or _hosted.GUEST_ACTOR
                # Async Red scans keep the parallel slot until they finish or
                # are cancelled; sync Blue/OSINT/Yellow release after the request.
                hold_parallel = bool(re.search(r"/targets/\d+/scan$|/target/\d+/scan$", path))
                _hosted.audit_guest(
                    "run_start", path=path,
                    detail=str((body or {}).get("target_id") or ""),
                    target_id=(body or {}).get("target_id"),
                )
        request.state.user = {"username": row["username"], "role": row["role"]}
        try:
            _hosted.mark_current_guest(_hosted.is_guest(row["role"]))
        except Exception:
            pass
        try:
            response = await call_next(request)
        except Exception:
            _server_error_alert(store, request, row["username"])
            if rate_entered:
                try:
                    _hosted.guest_rate_leave(rate_user)
                except Exception:
                    pass
            raise
        if row["role"] == "admin" and not path.startswith(_NOLOG_PREFIX) and path not in _NOLOG_PATHS:
            if method in _UNSAFE:
                _activity(store, request, "admin_change", status=int(response.status_code))
            elif method == "GET" and "text/html" in (response.headers.get("content-type") or ""):
                _activity(store, request, "admin_page_view", status=int(response.status_code))
        if int(getattr(response, "status_code", 200) or 200) >= 500:
            _server_error_alert(store, request, row["username"],
                                status=int(response.status_code))
        if rate_entered:
            started = hold_parallel and int(getattr(response, "status_code", 500)) in {200, 202}
            if not started:
                try:
                    _hosted.guest_rate_leave(rate_user)
                except Exception:
                    pass
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    existing = {getattr(route, "path", None) for route in app.router.routes}

    if "/healthz" not in existing:
        @app.get("/healthz", include_in_schema=False)
        def healthz():
            # Liveness only. No version, no config, no session needed.
            return {"ok": True}

    if "/login" not in existing:
        @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
        def login_page(request: Request, next: str = "/", error: str = ""):
            from .i18n import activate_request
            from .web.app import templates

            activate_request(request)
            return templates.TemplateResponse(
                request, "login.html",
                {"next": safe_next(next), "error": error},
            )

        @app.post("/login", include_in_schema=False)
        def login_submit(
            request: Request,
            username: str = Form(...),
            password: str = Form(...),
            next: str = Form("/"),
        ):
            return _attempt_login(getter(), request, username, password, next)

    if "/login/2fa" not in existing:
        @app.get("/login/2fa", response_class=HTMLResponse, include_in_schema=False)
        def login_2fa_page(request: Request, error: str = ""):
            from .i18n import activate_request
            from .web.app import templates

            activate_request(request)
            if not webauth.get_pending_2fa(request.cookies.get(webauth.PENDING_COOKIE)):
                return RedirectResponse(url="/login", status_code=303)
            return templates.TemplateResponse(request, "login_2fa.html", {"error": error})

        @app.post("/login/2fa", include_in_schema=False)
        def login_2fa_submit(request: Request, code: str = Form("")):
            return _complete_2fa(getter(), request,
                                 request.cookies.get(webauth.PENDING_COOKIE) or "", code)

        @app.post("/api/login/2fa", include_in_schema=False)
        async def api_login_2fa(request: Request):
            try:
                payload = await request.json()
            except Exception:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            return _complete_2fa(getter(), request, str(payload.get("pending") or ""),
                                 str(payload.get("code") or ""))

    if "/api/login" not in existing:
        @app.post("/api/login", include_in_schema=False)
        async def api_login(request: Request):
            try:
                payload = await request.json()
            except Exception:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            return _attempt_login(
                getter(),
                request,
                str(payload.get("username") or ""),
                str(payload.get("password") or ""),
                str(payload.get("next") or "/"),
            )

    if "/logout" not in existing:
        @app.post("/logout", include_in_schema=False)
        @app.get("/logout", include_in_schema=False)
        def logout(request: Request):
            token = request.cookies.get(webauth.COOKIE_NAME)
            if token:
                try:
                    srow = getter().get_session(token)
                    if srow:
                        _activity(getter(), request, "logout", username=srow["username"], role=srow["role"])
                except Exception:
                    pass
                try:
                    getter().delete_session(token)
                except Exception:
                    pass
            response = RedirectResponse(url="/login", status_code=303)
            response.delete_cookie(webauth.COOKIE_NAME, path="/")
            response.delete_cookie(webauth.CSRF_COOKIE, path="/")
            return response

    # Hosted mode (ANTBB_HOSTED=1) goes last so it is the outermost layer:
    # security headers on every response, strict CSRF, fail closed.
    from . import hosted
    hosted.install(app)


def assert_websocket(ws) -> bool:
    """Close and return False when this socket must not proceed.

    Returns True when the caller may accept the socket.
    """
    from .netbind import bind_violation

    host = _server_host(ws.scope)
    violation = bind_violation(host)
    if violation:
        return False
    if not webauth.auth_enabled():
        if host in {"testserver", "testclient"} or os.environ.get("ANTBB_TESTING", "").strip() in {
            "1", "true", "yes", "on",
        }:
            return True
        return False
    token = ws.cookies.get(webauth.COOKIE_NAME)
    if not token:
        header = ws.headers.get("authorization") or ""
        if header.lower().startswith("bearer "):
            token = header[7:].strip()
    try:
        row = webauth.session_user(_store_getter()(), token) if token else None
    except Exception:
        row = None
    return row is not None
