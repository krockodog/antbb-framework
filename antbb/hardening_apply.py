"""Reversible Härtung hinter Oversight, auf Judiths bestehender Remediation.

Wendet nur Schritte an, die `remediation_apply` schon fest kodiert hat:
  * ssh-password-auth → Drop-in `PasswordAuthentication no` (mit Backup)
  * sysctl-hardening → `/etc/sysctl.d/99-antbb-hardening.conf` (mit Backup)
  * host-firewall → nur wenn ufw da ist UND riskante Wildcard-Ports lauschen:
    die bestehende „firewall bind“-Aktion (localhost-allow + deny auf diesen Ports).
    `ufw enable` wird nicht blind ausgeführt.

Ohne Oversight oder ohne Scope `localhost`: denied, Runner wird nicht gerufen.
Ein Re-Check, der nicht `pass` ist, setzt closed nicht.
"""
from __future__ import annotations

import logging
import shutil
from typing import Callable, Optional

from . import remediation_apply
from .active_oversight import ACTIVE_LEGAL_NOTICE

log = logging.getLogger("antbb.hardening_apply")

_APPLY_IDS = ("ssh-password-auth", "sysctl-hardening")


def _ufw_present() -> bool:
    return shutil.which("ufw") is not None


def _risky_ports() -> list[int]:
    try:
        from .agents.blue.fwaudit import RISKY_PORTS, listeners
    except Exception:
        return []
    return sorted({p for scope, p in listeners() if scope == "wildcard" and p in RISKY_PORTS})


def _gate(active: bool, scope_check) -> Optional[dict]:
    if not active:
        return {
            "check_id": "*", "applied": False, "closed": False, "status": "denied",
            "reason": "BLOCKIERT (default-deny): Härtung ohne Oversight. Nichts verändert.",
            "commands": [], "backups": [], "evidence": {},
        }
    allowed = False
    if scope_check is not None:
        try:
            allowed = bool(scope_check("localhost"))
        except Exception:
            allowed = False
    if not allowed:
        return {
            "check_id": "*", "applied": False, "closed": False, "status": "denied",
            "reason": "BLOCKIERT (default-deny): localhost nicht im Scope.",
            "commands": [], "backups": [], "evidence": {},
        }
    return None


def _finding_for(result, check_id: str, extra: Optional[dict] = None) -> dict:
    ev = dict(getattr(result, "evidence", None) or {})
    ev["check_id"] = check_id
    if extra:
        ev.update(extra)
    return {
        "category": "blue-hardening-gap",
        "title": getattr(result, "title", check_id),
        "dedup_key": f"blue-hardening:{check_id}",
        "evidence": ev,
    }


def apply_reversible(results, *, active: bool = False, scope_check=None,
                     runner: Optional[Callable] = None,
                     recheck: Optional[Callable] = None,
                     params: Optional[dict] = None) -> list[dict]:
    """Wendet fehlgeschlagene, unterstützte Checks an und hängt den Re-Check an."""
    blocked = _gate(active, scope_check)
    if blocked:
        return [blocked]
    log.info("⚖ %s", ACTIVE_LEGAL_NOTICE)
    params = dict(params or {})
    out: list[dict] = []
    for result in results or []:
        if getattr(result, "status", "") != "fail":
            continue
        check_id = getattr(result, "check_id", "")
        if check_id in _APPLY_IDS:
            out.append(_apply_one(result, check_id, runner=runner, recheck=recheck, params=params))
        elif check_id == "host-firewall":
            out.append(_apply_firewall(result, runner=runner, recheck=recheck, params=params))
    return out


def _apply_one(result, check_id: str, *, runner, recheck, params) -> dict:
    finding = _finding_for(result, check_id)
    try:
        applied = remediation_apply.apply_fix(
            finding, params, runner=runner, recheck=recheck,
        )
    except remediation_apply.RemediationError as exc:
        return {
            "check_id": check_id, "applied": False, "closed": False, "status": "failed",
            "reason": str(exc), "commands": [], "backups": [],
            "evidence": {"before": "fail", "after": "failed", "check_id": check_id},
        }
    closed = applied.get("closed") is True
    ev = dict(applied.get("evidence") or {})
    ev.setdefault("before", "fail")
    ev["check_id"] = check_id
    ev["backups"] = list(applied.get("backups") or [])
    ev["commands"] = list(applied.get("commands") or [])
    ev["what_we_do"] = (
        "Drop-in und Backup über remediation_apply. "
        "Rollback: Backup-Datei zurückkopieren."
    )
    return {
        "check_id": check_id, "applied": True, "closed": closed,
        "status": "GESCHLOSSEN" if closed else "unverified",
        "reason": ("Re-Check pass." if closed else "Angewendet, Re-Check nicht pass."),
        "commands": ev["commands"], "backups": ev["backups"], "evidence": ev,
    }


def _apply_firewall(result, *, runner, recheck, params) -> dict:
    check_id = "host-firewall"
    if not _ufw_present():
        return {
            "check_id": check_id, "applied": False, "closed": False, "status": "unavailable",
            "reason": "ufw nicht installiert. Firewall-Bind nicht ausgeführt, nicht als gehärtet gewertet.",
            "commands": [], "backups": [],
            "evidence": {"before": "fail", "after": "unavailable", "check_id": check_id},
        }
    ports = _risky_ports()
    if not ports:
        return {
            "check_id": check_id, "applied": False, "closed": False, "status": "skipped",
            "reason": ("Kein riskanter Wildcard-Port. ufw enable wird nicht blind ausgeführt "
                       "(Lockout-Risiko)."),
            "commands": [], "backups": [],
            "evidence": {"before": "fail", "after": "skipped", "check_id": check_id, "ports": []},
        }
    finding = _finding_for(result, "risky-ports-exposed", {"ports": ports})
    try:
        applied = remediation_apply.apply_fix(
            finding, params, runner=runner, recheck=recheck,
        )
    except remediation_apply.RemediationError as exc:
        return {
            "check_id": check_id, "applied": False, "closed": False, "status": "failed",
            "reason": str(exc), "commands": [], "backups": [],
            "evidence": {"before": "fail", "after": "failed", "ports": ports, "check_id": check_id},
        }
    closed = applied.get("closed") is True
    ev = dict(applied.get("evidence") or {})
    ev["before"] = ev.get("before") or "fail"
    ev["ports"] = ports
    ev["check_id"] = check_id
    ev["bind"] = "ufw allow from 127.0.0.1 + deny <port>/tcp (remediation_apply)"
    ev["commands"] = list(applied.get("commands") or [])
    ev["backups"] = list(applied.get("backups") or [])
    return {
        "check_id": check_id, "applied": True, "closed": closed,
        "status": "GESCHLOSSEN" if closed else "unverified",
        "reason": ("Firewall-Bind im ufw-Status bestätigt." if closed
                   else "Regeln gesendet, Status nicht bestätigt."),
        "commands": ev["commands"], "backups": ev["backups"], "evidence": ev,
    }
