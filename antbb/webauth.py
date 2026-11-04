"""Authentifizierung fuer den antbb-Webserver.

Produktion verlangt ein Admin-Passwort aus der Umgebung
(ANTBB_ADMIN_PASSWORD_HASH, bevorzugt, oder ANTBB_ADMIN_PASSWORD).
Es gibt kein Default-Passwort und keinen eingebauten Account.

Sicherheit:
  * Passwoerter werden NUR als gesalzener PBKDF2-HMAC-SHA256-Hash gespeichert
    (stdlib hashlib, keine Fremd-Dependency), NIE im Klartext, NIE geloggt.
  * Session ueber ein zufaelliges, serverseitig gespeichertes Token
    (secrets.token_urlsafe) in einem HttpOnly-Cookie. Kein Secret im Cookie-Wert
    ausser dem opaken Token.
  * Rollen: admin | viewer. Human-only-Aktionen (brain-reset/delete) bleiben
    strikt admin-geschuetzt.
  * Admin-Bootstrap nur aus ENV oder CLI – NICHT hartkodiert.
  * Fehlender Benutzer laeuft trotzdem durch PBKDF2 (konstantzeitiger Vergleich).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sys
import time
from typing import Optional

from .store import Store

COOKIE_NAME = "antbb_session"
CSRF_COOKIE = "antbb_csrf"
_PW_ITER = 240000
_TRUE = {"1", "true", "yes", "on"}
_FAILS: dict[str, list[float]] = {}
# Fester Dummy, damit ein unbekannter Benutzer dieselbe Hash-Arbeit kostet.
_DUMMY_HASH, _DUMMY_SALT, _DUMMY_ITER = (
    None, None, _PW_ITER,
)


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUE


def credentials_configured() -> bool:
    """True when the process was given an admin password or password hash."""
    return bool(
        os.environ.get("ANTBB_ADMIN_PASSWORD_HASH", "").strip()
        or os.environ.get("ANTBB_ADMIN_PASSWORD", "")
    )


def auth_enabled() -> bool:
    """True when a credential is configured or ANTBB_AUTH is explicitly on.

    ANTBB_AUTH=0 does not turn authentication off once a password is set.
    Unset means off only for in-process tests that never configured a password;
    the official launcher still refuses to start in that case.
    """
    if credentials_configured():
        return True
    return os.environ.get("ANTBB_AUTH", "").strip().lower() in _TRUE


# ---- Passwort-Hashing (PBKDF2-HMAC-SHA256, stdlib) ------------------------
def hash_password(password: str, salt: Optional[str] = None,
                  iterations: int = _PW_ITER) -> tuple[str, str, int]:
    """Gibt (hash_hex, salt_hex, iterations) zurueck. Klartext wird nie geloggt."""
    if not password:
        raise ValueError("Leeres Passwort ist nicht erlaubt.")
    salt_bytes = bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt_bytes, iterations)
    return dk.hex(), salt_bytes.hex(), iterations


def verify_password(password: str, pw_hash: str, pw_salt: str,
                    iterations: int = _PW_ITER) -> bool:
    """Konstantzeit-Vergleich. Nie Klartext/Hash loggen."""
    try:
        dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"),
                                 bytes.fromhex(pw_salt), int(iterations))
    except Exception:
        return False
    return hmac.compare_digest(dk.hex(), pw_hash or "")


def format_password_hash(password: str) -> str:
    """pbkdf2_sha256:iterations:salt_hex:hash_hex — Klartext wird nicht geloggt.

    Colon separators stay literal when a shell sources antbb.env. The older
    dollar-separated form is still accepted by parse_password_hash.
    """
    digest, salt, iterations = hash_password(password)
    return f"pbkdf2_sha256:{iterations}:{salt}:{digest}"


def parse_password_hash(encoded: str) -> Optional[tuple[str, str, int]]:
    """Gibt (hash_hex, salt_hex, iterations) zurueck, sonst None."""
    text = (encoded or "").strip().strip("'\"")
    parts = text.split("$") if "$" in text else text.split(":")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return None
    try:
        iterations = int(parts[1])
    except ValueError:
        return None
    salt, digest = parts[2], parts[3]
    if iterations < 10000 or not salt or not digest:
        return None
    try:
        bytes.fromhex(salt)
        bytes.fromhex(digest)
    except ValueError:
        return None
    return digest, salt, iterations


def _dummy_material() -> tuple[str, str, int]:
    global _DUMMY_HASH, _DUMMY_SALT, _DUMMY_ITER
    if _DUMMY_HASH is None:
        _DUMMY_HASH, _DUMMY_SALT, _DUMMY_ITER = hash_password("not-a-real-password")
    return _DUMMY_HASH, _DUMMY_SALT, _DUMMY_ITER


# ---- Nutzerverwaltung -----------------------------------------------------
def create_user(store: Store, username: str, password: str,
                role: str = "viewer") -> int:
    username = (username or "").strip()
    if not username:
        raise ValueError("Leerer Benutzername.")
    h, salt, it = hash_password(password)
    return store.create_user(username, h, salt, role=role, pw_iter=it)


def set_password(store: Store, username: str, password: str) -> None:
    h, salt, it = hash_password(password)
    store.update_user_password(username, h, salt, pw_iter=it)


def authenticate(store: Store, username: str, password: str):
    """Gibt die User-Row bei Erfolg zurueck, sonst None.

    Unbekannte oder inaktive Benutzer laufen trotzdem durch PBKDF2, damit die
    Antwortzeit kein Benutzerverzeichnis verrät.
    """
    row = store.get_user((username or "").strip())
    if not row or not row["active"]:
        digest, salt, iterations = _dummy_material()
        verify_password(password, digest, salt, iterations)
        return None
    iterations = row["pw_iter"] if "pw_iter" in row.keys() else _PW_ITER
    if verify_password(password, row["pw_hash"], row["pw_salt"], iterations):
        return row
    return None


def login_rate_limited(key: str) -> bool:
    limit = int(os.environ.get("ANTBB_LOGIN_MAX_ATTEMPTS", "8"))
    window = float(os.environ.get("ANTBB_LOGIN_WINDOW", "600"))
    now = time.monotonic()
    stamps = [stamp for stamp in _FAILS.get(key, []) if now - stamp < window]
    _FAILS[key] = stamps
    return len(stamps) >= limit


def note_login_failure(key: str) -> None:
    _FAILS.setdefault(key, []).append(time.monotonic())


def clear_login_failures(key: str) -> None:
    _FAILS.pop(key, None)


def reset_login_throttle() -> None:
    """Test helper. Not used by the server."""
    _FAILS.clear()


def start_session(store: Store, row) -> str:
    token = secrets.token_urlsafe(32)
    store.create_session(token, row["username"], row["role"])
    return token


def session_user(store: Store, token: Optional[str]):
    """Gibt die Session-Row ({username, role, ...}) oder None zurueck."""
    return store.get_session(token) if token else None


def bootstrap_admin(store: Store) -> Optional[str]:
    """Legt den Admin aus der Umgebung an oder aktualisiert sein Passwort.

    ANTBB_ADMIN_PASSWORD_HASH (pbkdf2_sha256$iter$salt$hash) hat Vorrang vor
    ANTBB_ADMIN_PASSWORD. Der Klartext wird nie geloggt. Ohne Credential
    passiert nichts — der Launcher verweigert dann den Start.
    Benutzername: ANTBB_ADMIN_USER, sonst ``admin``.
    """
    encoded = os.environ.get("ANTBB_ADMIN_PASSWORD_HASH", "").strip()
    password = os.environ.get("ANTBB_ADMIN_PASSWORD", "")
    if not encoded and not password:
        return None
    user = os.environ.get("ANTBB_ADMIN_USER", "").strip() or "admin"
    if encoded:
        parsed = parse_password_hash(encoded)
        if parsed is None:
            raise ValueError(
                "ANTBB_ADMIN_PASSWORD_HASH must look like "
                "pbkdf2_sha256:iterations:salt_hex:hash_hex"
            )
        digest, salt, iterations = parsed
    else:
        digest, salt, iterations = hash_password(password)
    if store.get_user(user):
        store.update_user_password(user, digest, salt, pw_iter=iterations)
        store.set_user_role(user, "admin")
        return user
    store.create_user(user, digest, salt, role="admin", pw_iter=iterations)
    return user


# ---- CLI: Erst-Admin / Benutzer anlegen (NICHT hartkodiert) ---------------
def sys_stdin_password() -> str:
    password = sys.stdin.read()
    if password.endswith("\n"):
        password = password[:-1]
    return password


def _cli(argv: Optional[list] = None) -> int:
    """Minimale CLI: `python -m antbb.webauth add-user <name> [--role admin]`.

    Das Passwort wird interaktiv (getpass) ODER aus ANTBB_NEW_PASSWORD gelesen,
    NIE als Argument (damit es nicht in der Prozessliste/History landet).
    """
    import argparse
    import getpass
    ap = argparse.ArgumentParser(prog="antbb.webauth")
    sub = ap.add_subparsers(dest="cmd", required=True)
    au = sub.add_parser("add-user", help="Benutzer anlegen/aktualisieren")
    au.add_argument("username")
    au.add_argument("--role", choices=["admin", "viewer"], default="viewer")
    sub.add_parser("list-users", help="Benutzer auflisten")
    hp = sub.add_parser(
        "hash-password",
        help="PBKDF2-Hash nach stdout (Passwort von stdin oder Rueckfrage)",
    )
    hp.add_argument("--stdin", action="store_true",
                    help="Passwort von stdin lesen, ohne Echo und ohne Argument")
    args = ap.parse_args(argv)
    if args.cmd == "hash-password":
        if args.stdin:
            password = sys_stdin_password()
        else:
            password = os.environ.get("ANTBB_ADMIN_PASSWORD") or ""
            if not password:
                import getpass
                password = getpass.getpass("Passwort: ")
        if not password:
            print("Leeres Passwort ist nicht erlaubt.", file=sys.stderr)
            return 2
        print(format_password_hash(password))
        return 0
    store = Store()
    try:
        if args.cmd == "list-users":
            for u in store.list_users():
                print(f"{u['username']}\t{u['role']}\t"
                      f"{'aktiv' if u['active'] else 'inaktiv'}")
            return 0
        if args.cmd == "add-user":
            pw = os.environ.get("ANTBB_NEW_PASSWORD")
            if not pw:
                pw = getpass.getpass("Passwort: ")
            if store.get_user(args.username):
                set_password(store, args.username, pw)
                store.set_user_role(args.username, args.role)
                print(f"Benutzer '{args.username}' aktualisiert (Rolle {args.role}).")
            else:
                create_user(store, args.username, pw, role=args.role)
                print(f"Benutzer '{args.username}' angelegt (Rolle {args.role}).")
            return 0
    finally:
        store.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(_cli())
