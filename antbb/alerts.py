"""Sicherheits-Alarme: In-App (Banner/Punkt, nur admin) + optional ntfy-Push.

Kein SMTP/E-Mail. ntfy ist nur aktiv, wenn ANTBB_ALERT_NTFY_URL und
ANTBB_ALERT_NTFY_TOKEN in der Umgebung stehen. Versand im Hintergrund-Thread,
Timeout 3 s, Fehler werden nur (ohne Token) geloggt, der Request blockiert nie.
Dedupe: wie die In-App-Alarme (store.add_alert) – nur neu angelegte Alarme
werden gepusht.
"""
from __future__ import annotations

import logging
import os
import threading
import time
import urllib.request
from typing import Optional

log = logging.getLogger("antbb.alerts")

KIND_LABELS = {
    "login_limited": "Login-Bruteforce (Rate-Limit erreicht)",
    "login_bruteforce_2fa": "Login-Bruteforce (2FA-Code)",
    "admin_denied": "Zugriff auf Admin-Bereich verweigert",
    "owner_denied": "Zugriff auf fremden Lauf/Ziel verweigert",
    "wlan_denied": "WLAN-Kanal ohne Berechtigung",
    "invite_invalid": "Ungültige Einladungs-Versuche",
    "user_kicked": "Benutzer gekickt & gesperrt",
    "user_unlocked": "Benutzer entsperrt",
    "server_error": "Serverfehler (5xx/Exception)",
    "test": "Testalarm",
    "kill_switch": "KILL SWITCH: alle Agenten gestoppt",
    "kill_switch_reset": "Kill Switch zurückgesetzt",
}
_PRIO = {"info": "2", "warn": "4", "high": "5"}


def ntfy_configured() -> bool:
    return bool(os.environ.get("ANTBB_ALERT_NTFY_URL", "").strip()
                and os.environ.get("ANTBB_ALERT_NTFY_TOKEN", "").strip())


def _ntfy_send(kind: str, severity: str, username: Optional[str], ip: str, path: str) -> None:
    url = os.environ.get("ANTBB_ALERT_NTFY_URL", "").strip()
    token = os.environ.get("ANTBB_ALERT_NTFY_TOKEN", "").strip()
    if not url or not token:
        return
    who = username or "nicht angemeldet"
    when = time.strftime("%d.%m.%Y %H:%M:%S %Z")
    text = (f"Regel: {KIND_LABELS.get(kind, kind)}\n"
            f"User: {who}" + (f" · IP: {ip}" if ip else "") + "\n"
            + (f"Pfad: {path[:120]}\n" if path else "")
            + f"Zeit: {when}")
    req = urllib.request.Request(url, data=text.encode("utf-8"), method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Title", f"antbb Alarm: {KIND_LABELS.get(kind, kind)}"[:120].encode("ascii", "replace").decode())
    req.add_header("Priority", _PRIO.get(severity, "3"))
    req.add_header("Tags", "rotating_light" if severity == "high" else "warning")
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            resp.read(64)
    except Exception as exc:  # noqa: BLE001 – Token nie loggen
        log.warning("ntfy push failed: %s", type(exc).__name__)


def raise_alert(store, kind: str, *, username: Optional[str] = None, ip: str = "",
                path: str = "", detail: str = "", severity: str = "warn") -> Optional[int]:
    """Legt einen In-App-Alarm an (dedupliziert) und pusht ihn optional per ntfy."""
    try:
        aid = store.add_alert(kind, username=username, ip=ip, path=path,
                              detail=detail, severity=severity)
    except Exception as exc:  # noqa: BLE001
        log.warning("alert store failed: %s", type(exc).__name__)
        return None
    if aid and ntfy_configured():
        threading.Thread(target=_ntfy_send, args=(kind, severity, username, ip, path),
                         daemon=True).start()
    return aid
