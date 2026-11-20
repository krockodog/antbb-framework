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
  * Rollen: admin | member | viewer | guest_user.
      - admin: alles inkl. Benutzerverwaltung/Einladungen (/admin, /api/users).
      - member: Operator – Ziele anlegen, Scope setzen, Oversight, Tests
        starten (Red/Blue/Yellow/OSINT). KEIN User-Management, keine
        Policy/Papierkorb-Aktionen.
      - member_plus: wie member plus WLAN-Kanal (Laptop-Umfang). Offensiv-WLAN
        nur mit den bestehenden Gates. KEIN User-Management.
      - viewer und guest_user sind die Gast-Nutzrolle (Deny-by-Default-
        Allowlist in hosted/webguard).
    Human-only-Aktionen (brain-reset/delete) bleiben strikt admin-geschuetzt.
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

from .store import USER_ROLES, Store

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


# ---- Rollen-Helfer ----------------------------------------------------------
ROLES = USER_ROLES
OPS_ROLES = frozenset({"admin", "member", "member_plus"})
WLAN_ROLES = frozenset({"admin", "member_plus"})


def _norm_role(role: Optional[str]) -> str:
    return (role or "").strip().lower()


def is_admin(role: Optional[str]) -> bool:
    return _norm_role(role) == "admin"


def is_member(role: Optional[str]) -> bool:
    return _norm_role(role) == "member"


def is_member_plus(role: Optional[str]) -> bool:
    return _norm_role(role) == "member_plus"


def can_wlan(role: Optional[str]) -> bool:
    """WLAN-Kanal im Hosted-Modus: admin oder member_plus."""
    return _norm_role(role) in WLAN_ROLES


def can_authorize_scope(role: Optional[str]) -> bool:
    """Formale Scope-Autorisierung (neue Scope-Policy-Felder, authorized_by,
    rules_of_engagement): admin oder member_plus. Einfaches member darf weiterhin
    nur Basis-Scope-Eintraege (kind/value) anlegen, aber nicht formal autorisieren."""
    return _norm_role(role) in {"admin", "member_plus"}


def can_ops(role: Optional[str]) -> bool:
    """admin ODER member: Scope/Oversight/Ziele/Scans. Oversight-Gates bleiben."""
    return _norm_role(role) in OPS_ROLES


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


PASSWORD_MIN_LEN = 12


def change_own_password(store: Store, username: str, current: str,
                        new: str, confirm: str) -> Optional[str]:
    """Eigenes Passwort aendern. Gibt Fehler-Key (i18n) oder None zurueck.

    Prueft das aktuelle Passwort ueber authenticate(). Klartext wird nie
    geloggt oder gespeichert.
    """
    if authenticate(store, username, current or "") is None:
        return "profile.pw.err_current"
    if len(new or "") < PASSWORD_MIN_LEN:
        return "profile.pw.err_short"
    if new != confirm:
        return "profile.pw.err_mismatch"
    if (new or "").strip().lower() == (username or "").strip().lower():
        return "profile.pw.err_username"
    if new == current:
        return "profile.pw.err_same"
    set_password(store, username, new)
    return None


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


def login_rate_limited(key: str, scale: int = 1) -> bool:
    limit = int(os.environ.get("ANTBB_LOGIN_MAX_ATTEMPTS", "8")) * max(1, scale)
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


# ---- 2FA (TOTP) -------------------------------------------------------------
PENDING_COOKIE = "antbb_2fa"
_PENDING: dict[str, dict] = {}
PENDING_TTL = 300.0
PENDING_MAX_FAILS = 5


def totp_enabled(row) -> bool:
    try:
        return bool(row and "totp_enabled" in row.keys() and row["totp_enabled"])
    except Exception:
        return False


def start_pending_2fa(username: str, nxt: str = "/") -> str:
    """Kurzlebiges, serverseitig gehaltenes Pending-Token (zufaellig, 5 min)."""
    now = time.monotonic()
    for k in [k for k, v in _PENDING.items() if v["exp"] < now]:
        _PENDING.pop(k, None)
    token = secrets.token_urlsafe(32)
    _PENDING[token] = {"username": username, "exp": now + PENDING_TTL,
                       "fails": 0, "next": nxt or "/"}
    return token


def get_pending_2fa(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    entry = _PENDING.get(token)
    if not entry or entry["exp"] < time.monotonic():
        _PENDING.pop(token or "", None)
        return None
    return entry


def drop_pending_2fa(token: Optional[str]) -> None:
    _PENDING.pop(token or "", None)


def verify_second_factor(store: Store, username: str, code: str) -> Optional[str]:
    """Prueft TOTP (mit Replay-Schutz) oder einen Recovery-Code.

    Gibt "totp" / "recovery" zurueck oder None. Secrets/Codes werden nie geloggt.
    """
    from . import totp as _totp
    row = store.get_user(username)
    if not row or not row["active"] or not totp_enabled(row):
        return None
    secret = _totp.decrypt(row["totp_secret_enc"] or "")
    digits = "".join(ch for ch in (code or "") if ch.isdigit())
    if secret and len(digits) == _totp.DIGITS and len((code or "").strip()) <= 8:
        step = _totp.verify(secret, digits, row["totp_last_step"])
        if step is not None and store.set_totp_last_step(username, step):
            return "totp"
        return None
    updated = _totp.use_recovery(row["recovery_hashes"] or "[]", code)
    if updated is not None:
        store.set_recovery_hashes(username, updated)
        return "recovery"
    return None


def start_session(store: Store, row) -> str:
    token = secrets.token_urlsafe(32)
    store.create_session(token, row["username"], row["role"])
    # Erst-Login merken (nur Zeitstempel, fuer den Admin-Hinweis "neuer Benutzer").
    try:
        key = f"user.first_login.{row['username']}"
        if not store.get_setting(key, ""):
            store.set_setting(key, f"{time.time():.3f}")
    except Exception:  # noqa: BLE001 – Login nie daran scheitern lassen
        pass
    return token


def session_user(store: Store, token: Optional[str]):
    """Gibt die Session-Row ({username, role, ...}) oder None zurueck."""
    return store.get_session(token) if token else None


def bootstrap_admin(store: Store) -> Optional[str]:
    """Legt den Admin aus der Umgebung an, falls er noch fehlt.

    Existiert der Benutzer schon, bleibt sein Passwort unveraendert (nur die
    Rolle admin wird gesichert).

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
        # Bestehender Admin: Passwort NICHT ueberschreiben. Sonst setzt jeder
        # Neustart eine Passwortaenderung aus /profile wieder auf den Hash aus
        # antbb.env zurueck. Nur die Rolle wird auf admin gesichert.
        # Notfall-Reset weiterhin per CLI:
        #   ANTBB_NEW_PASSWORD=... python -m antbb.webauth add-user <name> --role admin
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
    au.add_argument("--role", choices=list(ROLES), default="viewer")
    sub.add_parser("list-users", help="Benutzer auflisten")
    r2 = sub.add_parser("reset-2fa", help="Notfall: 2FA eines Benutzers abschalten")
    r2.add_argument("username")
    ul = sub.add_parser("unlock", help="Notfall: gesperrten Benutzer entsperren")
    ul.add_argument("username")
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
                      f"{'aktiv' if u['active'] else 'inaktiv'}\t"
                      f"2FA={'an' if u['totp_enabled'] else 'aus'}")
            return 0
        if args.cmd == "reset-2fa":
            if not store.get_user(args.username):
                print(f"Benutzer '{args.username}' nicht gefunden.", file=sys.stderr)
                return 2
            store.disable_totp(args.username)
            print(f"2FA fuer '{args.username}' zurueckgesetzt.")
            return 0
        if args.cmd == "unlock":
            if not store.get_user(args.username):
                print(f"Benutzer '{args.username}' nicht gefunden.", file=sys.stderr)
                return 2
            store.set_user_disabled(args.username, False)
            print(f"Benutzer '{args.username}' entsperrt.")
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
