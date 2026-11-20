"""TOTP (RFC 6238) + Recovery-Codes, nur stdlib fuer die OTP-Mathematik.

* HMAC-SHA1, 6 Ziffern, 30 s, Toleranz ±1 Zeitschritt.
* Replay-Schutz: der zuletzt akzeptierte Zeitschritt wird gespeichert; ein
  Code fuer denselben oder einen aelteren Schritt wird abgelehnt.
* Secrets liegen in der DB nur verschluesselt (Fernet aus `cryptography`, das
  ohnehin in requirements.txt steht). Schluessel: ANTBB_TOTP_KEY (Env) oder
  eine serverseitige Schluesseldatei im Daten-Volume (chmod 600), nie im Repo.
* Recovery-Codes nur als SHA-256-Hash gespeichert, einmal angezeigt, einmal
  nutzbar. Nie Secrets/Codes loggen.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from typing import Optional
from urllib.parse import quote

STEP = 30
DIGITS = 6
WINDOW = 1
ISSUER = "antbb All and One"


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _b32decode(secret: str) -> bytes:
    s = (secret or "").strip().replace(" ", "").upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s)


def hotp(secret: str, counter: int) -> str:
    key = _b32decode(secret)
    digest = hmac.new(key, struct.pack(">Q", int(counter)), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(code).zfill(DIGITS)


def current_step(now: Optional[float] = None) -> int:
    return int((now if now is not None else time.time()) // STEP)


def totp(secret: str, now: Optional[float] = None) -> str:
    return hotp(secret, current_step(now))


def verify(secret: str, code: str, last_step: Optional[int] = None,
           now: Optional[float] = None) -> Optional[int]:
    """Gibt den akzeptierten Zeitschritt zurueck oder None (falsch/Replay)."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != DIGITS or not secret:
        return None
    step = current_step(now)
    for delta in range(-WINDOW, WINDOW + 1):
        s = step + delta
        if last_step is not None and s <= int(last_step):
            continue
        if hmac.compare_digest(hotp(secret, s), code):
            return s
    return None


def otpauth_uri(secret: str, username: str) -> str:
    label = quote(f"{ISSUER}:{username}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


# ---- Recovery-Codes ---------------------------------------------------------
def new_recovery_codes(n: int = 8) -> list[str]:
    out = []
    for _ in range(n):
        raw = secrets.token_hex(5).upper()  # 10 Hex-Zeichen
        out.append(f"{raw[:5]}-{raw[5:]}")
    return out


def _norm_rc(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def hash_recovery(code: str) -> str:
    return hashlib.sha256(("antbb-rc:" + _norm_rc(code)).encode()).hexdigest()


def use_recovery(stored_json: str, code: str) -> Optional[str]:
    """Gibt das aktualisierte JSON zurueck, wenn der Code gueltig war, sonst None."""
    try:
        hashes = json.loads(stored_json or "[]")
    except Exception:
        hashes = []
    if not _norm_rc(code) or len(_norm_rc(code)) != 10:
        return None
    h = hash_recovery(code)
    for i, existing in enumerate(hashes):
        if hmac.compare_digest(existing, h):
            del hashes[i]
            return json.dumps(hashes)
    return None


# ---- Verschluesselung des Secrets -----------------------------------------
_FERNET = None


def _key_file() -> str:
    try:
        from . import config
        base = str(config.DATA_DIR)
    except Exception:
        base = os.environ.get("ANTBB_DATA") or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "data")
    return os.path.join(base, ".totp.key")


def _fernet():
    global _FERNET
    if _FERNET is not None:
        return _FERNET
    from cryptography.fernet import Fernet
    env = os.environ.get("ANTBB_TOTP_KEY", "").strip()
    if env:
        key = env.encode()
    else:
        path = _key_file()
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                key = fh.read().strip()
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            key = Fernet.generate_key()
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
    _FERNET = Fernet(key)
    return _FERNET


def encrypt(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt(blob: str) -> Optional[str]:
    if not blob:
        return None
    try:
        return _fernet().decrypt(blob.encode()).decode()
    except Exception:
        return None


def reset_cache() -> None:
    """Test-Helfer."""
    global _FERNET
    _FERNET = None
