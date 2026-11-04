"""Bind policy for the web UI and API.

The pentest console listens on loopback unless the operator opts in.
Non-loopback binds are refused, not silently widened.
"""
from __future__ import annotations

import os
import sys

_TRUTHY = {"1", "true", "yes", "on"}
_WARNED: set[str] = set()


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def is_loopback(host: str) -> bool:
    """True for localhost, ::1, and the entire 127.0.0.0/8 block."""
    value = (host or "").strip().lower().strip("[]")
    if value in {"127.0.0.1", "localhost", "::1"}:
        return True
    if value.startswith("127."):
        parts = value.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return True
    return False


def expose_enabled() -> bool:
    """Explicit opt-in for a non-loopback bind. Either flag is enough."""
    return _truthy("ANTBB_EXPOSE") or _truthy("YQ_EXPOSE")


def resolve_bind_host(raw: str | None = None) -> str:
    """Return the host uvicorn should bind.

    Default is 127.0.0.1. Any other address requires ANTBB_EXPOSE=1
    (or YQ_EXPOSE=1) and prints a warning on stderr.
    """
    host = (raw if raw is not None else configured_host()).strip() or "127.0.0.1"
    if host.lower() == "localhost":
        host = "127.0.0.1"
    if is_loopback(host):
        return host
    if not expose_enabled():
        raise SystemExit(
            f"ANTBB_EXPOSE is 0 (default): loopback only. "
            f"Set ANTBB_EXPOSE=1 to bind to {host}. Prefer an SSH tunnel."
        )
    _warn_nonlocal(host)
    return host


def argv_host() -> str | None:
    """Host passed as ``--host`` on the process command line, if any."""
    argv = sys.argv
    for index, arg in enumerate(argv):
        if arg == "--host" and index + 1 < len(argv):
            return argv[index + 1]
        if arg.startswith("--host="):
            return arg.split("=", 1)[1]
    return None


def configured_host() -> str:
    for key in ("ANTBB_HOST", "ANTBB_WEB_HOST", "ALLONE_HOST", "YQ_HOST"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return "127.0.0.1"


def bind_violation(server_host: str | None) -> str | None:
    """Reason the live socket must be rejected, or None when it is allowed.

    Test clients report ``testserver`` / ``testclient`` and are not a bind.
    """
    host = (server_host or "").strip().lower().strip("[]")
    if host in {"", "testserver", "testclient"}:
        return None
    if is_loopback(host):
        return None
    if expose_enabled():
        _warn_nonlocal(host)
        return None
    return (
        f"ANTBB_EXPOSE is 0 (default): loopback only. "
        f"Set ANTBB_EXPOSE=1 to bind to {server_host}. Prefer an SSH tunnel."
    )


def _warn_nonlocal(host: str) -> None:
    if host in _WARNED:
        return
    _WARNED.add(host)
    print(
        f"WARNING: ANTBB_EXPOSE is 1 (or YQ_EXPOSE=1): binding to {host}, "
        "not loopback. This exposes an authorized-pentest console. "
        "Prefer 127.0.0.1 and an SSH tunnel.",
        file=sys.stderr,
        flush=True,
    )


def assert_not_root() -> None:
    """Refuse to serve as root unless ANTBB_ALLOW_ROOT=1, which only warns."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        return
    if _truthy("ANTBB_ALLOW_ROOT"):
        print(
            "WARNING: the web UI is running as root because ANTBB_ALLOW_ROOT=1. "
            "Run it as an unprivileged user. Monitor-mode WLAN captures stay in "
            "the separate sudoers wrapper, not in this process.",
            file=sys.stderr,
            flush=True,
        )
        return
    raise SystemExit(
        "Refusing to start the web UI as root. Run it as a normal user "
        "(see deploy/antbb.service). Raw-socket WLAN scans are isolated in "
        "the sudoers wrapper and do not require this process to be root. "
        "ANTBB_ALLOW_ROOT=1 overrides this check and logs a warning."
    )


def assert_runtime_safe(host: str | None = None) -> str:
    """Checks used by the official entry points before the socket opens."""
    from antbb.webauth import credentials_configured

    assert_not_root()
    if os.environ.get("ANTBB_TESTING", "").strip().lower() in _TRUTHY:
        raise SystemExit(
            "Refusing to start: ANTBB_TESTING=1 is for the test suite only."
        )
    if not credentials_configured():
        raise SystemExit(
            "Refusing to start: set ANTBB_ADMIN_PASSWORD_HASH "
            "(or ANTBB_ADMIN_PASSWORD) in the environment. "
            "There is no default password. Generate a hash with: "
            "python -m antbb.webauth hash-password"
        )
    return resolve_bind_host(host if host is not None else configured_host())
