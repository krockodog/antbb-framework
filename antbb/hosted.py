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

# The login page renders base.html. Its stylesheet, background images and the
# favicon are reachable without a session. The Next.js landing also needs the
# hashed compile output under /_next/static/ (CSS/JS/fonts); those files have
# no secrets. API routes and HTML pages stay session-gated.
_LOGIN_ASSET_RE = re.compile(
    r"^/static/(style\.css|colony/[A-Za-z0-9_-]+\.(jpg|webp))$|^/favicon\.ico$"
)
_NEXT_STATIC_RE = re.compile(
    r"^/_next/static/[A-Za-z0-9._/-]+\.(css|js|mjs|woff2|woff|ttf|otf|png|jpg|jpeg|webp|ico|svg|map)$"
)


def login_asset(path: str) -> bool:
    path = path or ""
    if ".." in path or "\\" in path:
        return False
    return bool(_LOGIN_ASSET_RE.match(path) or _NEXT_STATIC_RE.match(path))


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


# ---------------------------------------------------------------------------
# Guest usage role (hosted): deny-by-default allowlist.
# The live Gast account is stored as role=viewer; guest_user is an alias.
# Guests may use the queens (defensive / assess) but must not change the
# programme, scope, or grant offensive Oversight (§202a-c StGB: the admin
# remains responsible).
# ---------------------------------------------------------------------------

GUEST_ROLES = frozenset({"viewer", "guest_user"})
GUEST_ACTOR = "Gast"
GUEST_RUN_MARK = "gestartet von Gast"
GUEST_UPLOAD_MAX_BYTES = 25 * 1024 * 1024  # 25 MiB
GUEST_MAX_PARALLEL = 1
GUEST_RUNS_PER_HOUR = 10

import json
import threading
import time
import contextvars
from pathlib import Path as _Path

_current_guest: contextvars.ContextVar[bool] = contextvars.ContextVar('antbb_guest', default=False)

_GUEST_LOCK = threading.Lock()
_GUEST_PARALLEL: dict[str, int] = {}
_GUEST_HOURLY: dict[str, list[float]] = {}


def is_guest(role: Optional[str]) -> bool:
    return (role or "").strip().lower() in GUEST_ROLES


def mark_current_guest(flag: bool) -> None:
    _current_guest.set(bool(flag))


def current_request_is_guest() -> bool:
    return bool(_current_guest.get())


def is_admin_role(role: Optional[str]) -> bool:
    return (role or "").strip().lower() == "admin"


def is_ops_role(role: Optional[str]) -> bool:
    """admin oder member (Operator). member ist bewusst KEINE Gast-Rolle."""
    return (role or "").strip().lower() in {"admin", "member", "member_plus"}


def guest_actor_name(_username: Optional[str] = None) -> str:
    """Audit / report actor. Always 'Gast' for this role, as required."""
    return GUEST_ACTOR


_GUEST_DENY = tuple(re.compile(p) for p in (
    r"^/api/targets$",
    r"^/target/add$",
    r"^/api/targets/\d+/scopes(?:/|$)",
    r"^/target/\d+/scope(?:/|$)",
    r"^/api/targets/\d+/oversight$",
    r"^/target/\d+/oversight$",
    r"^/api/queens/[^/]+/oversight$",
    r"^/api/queens/[^/]+/scope$",
    r"^/api/targets/\d+/mode$",
    r"^/target/\d+/mode$",
    r"^/target/\d+/archive$",
    r"^/target/\d+/restore$",
    r"^/isms$",
    r"^/api/undo$",
    r"^/undo$",
    r"^/api/blue/findings/\d+/apply$",
    r"^/api/blue/findings/\d+/remediate-recheck$",
    r"^/api/findings/\d+/to-blue$",
    r"^/api/blue/jobs(?:/|$)",
    r"^/api/blue/watcher$",
    r"^/api/blue/greenbone(?:/|$)",
    r"^/api/remote(?:/|$)",
    r"^/remote/set$",
    r"^/api/brain/",
    r"^/api/soldiers/",
    r"^/api/wlan(?:/|$)",
    r"^/assets(?:/|$)",
    r"^/api/assets(?:/|$)",
    r"^/api/users(?:/|$)",
    r"^/admin(?:/|$)",
    r"^/api/admin(?:/|$)",
    r"^/api/settings(?:/|$)",
    r"^/settings(?:/|$)",
    r"^/api/secrets(?:/|$)",
    r"^/api/keys(?:/|$)",
    r"^/api/deploy(?:/|$)",
    r"^/api/git(?:/|$)",
    r"^/lab(?:/|$)",
    r"^/api/burp(?:/|$)",
    r"^/api/maltego(?:/|$)",
))

_GUEST_POST_ALLOW = tuple(re.compile(p) for p in (
    r"^/login$",
    r"^/logout$",
    r"^/api/login$",
    r"^/api/logout$",
    r"^/login/2fa$",
    r"^/api/login/2fa$",
    r"^/profile/2fa/(?:setup|cancel|confirm|disable)$",
    r"^/api/targets/\d+/scan$",
    r"^/api/targets/\d+/scan/cancel$",
    r"^/target/\d+/scan$",
    r"^/target/\d+/scan/cancel$",
    r"^/api/runs/[^/]+/cancel$",
    r"^/api/blue/run$",
    r"^/osint/run$",
    r"^/api/osint/run$",
    r"^/yellow/upload$",
    r"^/api/classify$",
    r"^/api/queens/yellow/classify$",
    r"^/yellow/case/[^/]+/orchestrate/step$",
    r"^/api/reports/generate$",
    r"^/api/targets/\d+/reports$",
    r"^/api/targets/\d+/branded-report/export$",
))

_GUEST_RUN_START = tuple(re.compile(p) for p in (
    r"^/api/targets/\d+/scan$",
    r"^/target/\d+/scan$",
    r"^/api/blue/run$",
    r"^/osint/run$",
    r"^/api/osint/run$",
    r"^/yellow/upload$",
    r"^/api/classify$",
    r"^/api/queens/yellow/classify$",
))

_TRUTHY = {"1", "true", "yes", "on", "y"}


def _truthy_val(value) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    return str(value).strip().lower() in _TRUTHY


def guest_write_allowed(path: str, method: str) -> bool:
    """Deny-by-default path check for unsafe methods. GET is not decided here."""
    method = (method or "").upper()
    path = path or ""
    if method in {"GET", "HEAD", "OPTIONS"}:
        return True
    if any(rx.search(path) for rx in _GUEST_DENY):
        return False
    if method == "POST" and any(rx.search(path) for rx in _GUEST_POST_ALLOW):
        return True
    return False


def guest_is_run_start(path: str, method: str) -> bool:
    return (method or "").upper() == "POST" and any(rx.search(path or "") for rx in _GUEST_RUN_START)


def guest_payload_denied(path: str, body: Optional[dict]) -> Optional[str]:
    """Extra body checks on allowlisted routes. None = allowed."""
    body = body or {}
    path = path or ""
    if re.search(r"/scan$", path) and "cancel" not in path:
        if any(_truthy_val(body.get(k)) for k in (
            "active", "fuzz", "offensive", "oversight_active", "oversight_ack",
        )):
            return (
                "Der Gast darf keine offensiven Läufe starten und kein "
                "Oversight für Offensiv-Läufe erteilen (§202a-c StGB)."
            )
    if path.endswith("/api/blue/run") or path.endswith("/blue/run"):
        if _truthy_val(body.get("apply_fixes")) or _truthy_val(body.get("apply")):
            return (
                "Der Gast darf keine Korrekturen, Quarantäne oder Remediation "
                "anwenden (apply_fixes ist Admin-only)."
            )
        depth = str(body.get("depth") or "light").lower().strip()
        if depth in {"intensiv", "intensive", "deep", "full", "intense"}:
            return "Der Gast darf Blue-Checks nur im Modus assess/light starten."
    return None


def _rate_dir() -> _Path:
    try:
        from . import config
        return _Path(str(config.DATA_DIR))
    except Exception:
        return _Path(os.environ.get("ANTBB_DATA") or "/tmp")


def audit_guest(action: str, *, detail: str = "", path: str = "",
                target_id: object = None, run_id: str = "") -> None:
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "user": GUEST_ACTOR,
        "action": action,
        "detail": detail,
        "path": path,
        "target_id": target_id,
        "run_id": run_id,
    }
    try:
        path_f = _rate_dir() / "audit.log"
        path_f.parent.mkdir(parents=True, exist_ok=True)
        with path_f.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def guest_rate_check(username: str) -> Optional[str]:
    """Return an error message when the guest is over the run budget."""
    key = (username or GUEST_ACTOR).strip().lower() or "gast"
    now = time.time()
    hour = now - 3600
    with _GUEST_LOCK:
        stamps = [t for t in _GUEST_HOURLY.get(key, []) if t >= hour]
        _GUEST_HOURLY[key] = stamps
        parallel = int(_GUEST_PARALLEL.get(key, 0))
        if parallel >= GUEST_MAX_PARALLEL:
            return (
                "Gast-Rate-Limit: höchstens ein paralleler Lauf "
                f"(aktuell {parallel})."
            )
        if len(stamps) >= GUEST_RUNS_PER_HOUR:
            return (
                f"Gast-Rate-Limit: höchstens {GUEST_RUNS_PER_HOUR} Läufe pro Stunde."
            )
    return None


def guest_rate_enter(username: str) -> Optional[str]:
    err = guest_rate_check(username)
    if err:
        return err
    key = (username or GUEST_ACTOR).strip().lower() or "gast"
    with _GUEST_LOCK:
        _GUEST_HOURLY.setdefault(key, []).append(time.time())
        _GUEST_PARALLEL[key] = int(_GUEST_PARALLEL.get(key, 0)) + 1
    return None


def guest_rate_leave(username: str) -> None:
    key = (username or GUEST_ACTOR).strip().lower() or "gast"
    with _GUEST_LOCK:
        _GUEST_PARALLEL[key] = max(0, int(_GUEST_PARALLEL.get(key, 0)) - 1)


def reset_guest_rate() -> None:
    with _GUEST_LOCK:
        _GUEST_PARALLEL.clear()
        _GUEST_HOURLY.clear()


def guest_upload_limit_bytes() -> int:
    raw = os.environ.get("ANTBB_GUEST_UPLOAD_MB", "").strip()
    if raw:
        try:
            return max(1, int(float(raw))) * 1024 * 1024
        except ValueError:
            pass
    return GUEST_UPLOAD_MAX_BYTES


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
