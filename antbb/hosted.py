"""Hosted mode (ANTBB_HOSTED=1) for an internet-facing deployment.

Hosted mode is meant for one setup: the app binds 127.0.0.1:1001 and a
TLS reverse proxy on the same host (Caddy, or Tailscale Funnel) is the
only thing that reaches it. It tightens what the normal loopback setup
already does, and it fails closed:

* Start is refused unless ANTBB_ADMIN_PASSWORD_HASH holds a valid hash.
  A plaintext ANTBB_ADMIN_PASSWORD, ANTBB_TESTING and ANTBB_EXPOSE are refused.
* Session cookies are always Secure, HttpOnly and SameSite=Strict.
* Every response carries CSP, HSTS, X-Frame-Options, X-Content-Type-Options
  and Referrer-Policy, including the login page and error responses.
* Cookie-authenticated POST/PUT/PATCH/DELETE must prove same origin
  (Origin or Referer, or the X-CSRF-Token double-submit header).
* Failed logins are also counted per username across all client IPs.
* Every scan needs the Oversight tick and at least one in-scope entry,
  server-side, also for runs the UI would call defensive.
* Starting a remote tunnel from the web UI and the OpenAPI docs are off.
"""
from __future__ import annotations

import os
import re
from typing import Optional
from urllib.parse import urlparse

_TRUE = {"1", "true", "yes", "on"}

# Next.js static export and the Jinja templates use inline <script>/<style>
# and inline event handlers; the brain view decodes Draco meshes with WASM.
# Everything else is same-origin only. No third-party hosts are allowed.
CSP = "; ".join((
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self' blob:",
    "worker-src 'self' blob:",
    "media-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    # The brain view embeds same-origin pages; nothing else may frame the app.
    "frame-ancestors 'self'",
))

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    # same-origin, not no-referrer: with no-referrer browsers send
    # "Origin: null" on same-origin POSTs, which the CSRF check must reject.
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}

# Routes that would open the console to more of the internet, or that only
# document the API surface. Hosted mode answers 403 / 404 for them.
BLOCKED_POSTS = (
    "/remote/set",
    "/api/remote",
    "/api/remote/tunnel/start",
)
HIDDEN_PATHS = {"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}

MIN_HASH_ITERATIONS = 200_000

# The login page renders base.html. Only its stylesheet, background images and
# the favicon are reachable without a session; no script, no API, no data.
_LOGIN_ASSET_RE = re.compile(
    r"^/static/(style\.css|colony/[A-Za-z0-9_-]+\.(jpg|webp))$|^/favicon\.ico$"
)


def login_asset(path: str) -> bool:
    return bool(_LOGIN_ASSET_RE.match(path or ""))


def enabled() -> bool:
    return os.environ.get("ANTBB_HOSTED", "").strip().lower() in _TRUE


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUE


def readiness_error() -> Optional[str]:
    """Why hosted mode must not start, or None when it may."""
    from .webauth import parse_password_hash

    encoded = os.environ.get("ANTBB_ADMIN_PASSWORD_HASH", "").strip()
    if not encoded:
        return (
            "ANTBB_HOSTED=1 requires ANTBB_ADMIN_PASSWORD_HASH. There is no default "
            "password. Create one with: python -m antbb.webauth hash-password"
        )
    parsed = parse_password_hash(encoded)
    if parsed is None:
        return (
            "ANTBB_ADMIN_PASSWORD_HASH is not a valid "
            "pbkdf2_sha256:iterations:salt_hex:hash_hex value."
        )
    if parsed[2] < MIN_HASH_ITERATIONS:
        return (
            f"ANTBB_ADMIN_PASSWORD_HASH uses {parsed[2]} iterations; hosted mode "
            f"needs at least {MIN_HASH_ITERATIONS}. Generate a new hash."
        )
    if os.environ.get("ANTBB_ADMIN_PASSWORD", ""):
        return (
            "ANTBB_HOSTED=1 does not accept a plaintext ANTBB_ADMIN_PASSWORD. "
            "Remove it and keep only ANTBB_ADMIN_PASSWORD_HASH."
        )
    if _truthy("ANTBB_TESTING"):
        return "ANTBB_HOSTED=1 refuses ANTBB_TESTING=1."
    if _truthy("ANTBB_EXPOSE") or _truthy("YQ_EXPOSE"):
        return (
            "ANTBB_HOSTED=1 binds 127.0.0.1 only and refuses ANTBB_EXPOSE=1. "
            "The reverse proxy (Caddy or Tailscale Funnel) is the public side."
        )
    return None


def assert_ready() -> None:
    if not enabled():
        return
    reason = readiness_error()
    if reason:
        raise SystemExit(f"Refusing to start (hosted mode): {reason}")


def _same_origin(value: str, request) -> bool:
    parsed = urlparse(value or "")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    host = request.headers.get("host") or request.url.netloc
    return parsed.netloc == host


def strict_csrf_ok(request) -> bool:
    """Same-origin proof for a cookie-authenticated unsafe request."""
    import hmac

    from . import webauth

    if (request.headers.get("sec-fetch-site") or "").strip().lower() == "cross-site":
        return False
    origin = request.headers.get("origin")
    if origin:
        return _same_origin(origin, request)
    referer = request.headers.get("referer")
    if referer:
        return _same_origin(referer, request)
    token = request.headers.get("x-csrf-token") or ""
    cookie = request.cookies.get(webauth.CSRF_COOKIE) or ""
    return bool(token and cookie and hmac.compare_digest(token, cookie))


def require_scan_gates(store, target_id: int) -> None:
    """Hosted mode: no scan of any kind without Oversight and scope."""
    if not enabled():
        return
    from .oversight import OversightError

    if not store.is_confirmed(target_id):
        raise OversightError(
            "BLOCKIERT (Hosted-Modus): Oversight-Häkchen fehlt. Ohne Oversight "
            "startet kein Scan, auch kein defensiver."
        )
    allowed = [row for row in store.list_scopes(target_id) if row["allowed"]]
    if not allowed:
        raise OversightError(
            "BLOCKIERT (Hosted-Modus): Scope ist leer. Default-deny lässt keinen "
            "Scan zu. Zuerst einen erlaubten Scope-Eintrag anlegen."
        )


def install(app) -> None:
    """Outermost middleware. Call after webguard.install(app)."""
    if not enabled() or getattr(app.state, "antbb_hosted", False):
        return
    app.state.antbb_hosted = True

    from fastapi import Request
    from fastapi.responses import JSONResponse

    from . import webauth

    @app.middleware("http")
    async def _hosted(request: Request, call_next):
        path = request.url.path
        method = request.method.upper()
        reason = readiness_error()
        if reason:
            response = JSONResponse({"error": f"Hosted mode refused: {reason}"}, status_code=503)
        elif path in HIDDEN_PATHS:
            response = JSONResponse({"error": "Not available in hosted mode."}, status_code=404)
        elif method == "POST" and path in BLOCKED_POSTS:
            response = JSONResponse(
                {"error": "Remote access is managed by the host proxy in hosted mode."},
                status_code=403,
            )
        elif (
            method in {"POST", "PUT", "PATCH", "DELETE"}
            and request.cookies.get(webauth.COOKIE_NAME)
            and path not in {"/login", "/api/login"}
            and not strict_csrf_ok(request)
        ):
            response = JSONResponse({"error": "Cross-site request was rejected."}, status_code=403)
        else:
            response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        if not path.startswith(("/_next/", "/static/")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response
