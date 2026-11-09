"""Login wall in front of the web UI and API.

Every route except the health check requires a session. State-changing
requests that ride the session cookie must come from the same origin
(or present the CSRF token / a Bearer token). The official launcher
refuses to start when no admin credential is configured; a process that
is reached without one answers 503 instead of serving the console.
"""
from __future__ import annotations

import hmac
import os
import secrets
import sys
from html import escape
from typing import Callable, Optional
from urllib.parse import quote, urlparse

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

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
    if path == "/login" and method in {"GET", "HEAD", "POST"}:
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


def _needs_admin(path: str, method: str) -> bool:
    if not path.startswith("/api/brain"):
        return False
    if method == "DELETE":
        return True
    if method == "POST" and "/reset" in path:
        return True
    return False


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
        return _fail_login(
            request, status=429,
            detail=t("login.error_limited"), nxt=nxt,
        )
    if not row:
        webauth.note_login_failure(key)
        if global_key:
            webauth.note_login_failure(global_key)
        return _fail_login(
            request, status=401,
            detail=t("login.error_bad"), nxt=nxt,
        )
    webauth.clear_login_failures(key)
    if global_key:
        webauth.clear_login_failures(global_key)
    token = webauth.start_session(store, row)
    dest = safe_next(nxt)
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
            return JSONResponse(
                {"error": "Only an admin may run this action."},
                status_code=403,
            )
        request.state.user = {"username": row["username"], "role": row["role"]}
        response = await call_next(request)
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
