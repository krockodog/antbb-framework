"""Quarantäne und Netz-Isolation (Blue), nicht-destruktiv.

Pflicht: Human Oversight (`active=True`) und Scope (default-deny).
Ohne beides wird nichts verschoben und keine Firewall-Regel gesetzt.

Was dieser Code wirklich tut:
  * Datei: `shutil.move` in ein kontrolliertes Quarantäne-Verzeichnis
    (`ANTBB_QUARANTINE_DIR` oder `~/.local/share/antbb/quarantine`).
    Manifest mit Originalpfad, Modus und SHA-256. Kein Löschen.
    Rückholen über `restore_file`.
  * Netz: nur wenn `ufw` vorhanden ist, `ufw insert 1 deny from <eine IP>`.
    Vorher/Nachher ist die Ausgabe von `ufw status`. Rollback:
    `ufw delete deny from <IP>`. Ohne ufw: Status `unavailable`, applied false.
    Loopback, Unspecified und Multicast werden nicht isoliert.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import subprocess
import time
import uuid
import ipaddress
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger("antbb.quarantine")

_PROTECTED_PREFIXES = (
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot",
    "/proc", "/sys", "/dev", "/run", "/var/lib", "/var/log",
)


@dataclass
class ActionResult:
    ok: bool
    applied: bool
    status: str
    reason: str
    action: str = ""
    reversible: bool = False
    verified: bool = False
    closed: bool = False
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _notice() -> None:
    from .active_oversight import ACTIVE_LEGAL_NOTICE
    log.info("⚖ %s", ACTIVE_LEGAL_NOTICE)


def quarantine_root(explicit: Optional[str] = None) -> Path:
    """Kontrollierte Quarantäne-Wurzel. Kein `/`, kein Systemverzeichnis."""
    if explicit:
        base = Path(explicit)
    else:
        env = os.environ.get("ANTBB_QUARANTINE_DIR", "").strip()
        base = Path(env) if env else Path.home() / ".local" / "share" / "antbb" / "quarantine"
    base = base.expanduser().resolve()
    if base == Path("/") or str(base) in _PROTECTED_PREFIXES:
        raise ValueError(f"Quarantäne-Wurzel nicht erlaubt: {base}")
    base.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    return base


def _under_protected(path: str) -> bool:
    real = os.path.realpath(path)
    for prefix in _PROTECTED_PREFIXES:
        if real == prefix or real.startswith(prefix + os.sep):
            return True
    return False


def _in_scope(path: str, scope_check: Optional[Callable[[str], bool]]) -> bool:
    if scope_check is None:
        return False
    try:
        return bool(scope_check(path))
    except Exception:
        return False


def _denied(action: str, reason: str, evidence: Optional[dict] = None) -> ActionResult:
    return ActionResult(ok=False, applied=False, status="denied", reason=reason,
                        action=action, evidence=evidence or {})


def _write_manifest(root: Path, payload: dict) -> Path:
    path = root / f"{payload['id']}.manifest.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def find_manifest_for(original: str, root: Optional[str] = None) -> Optional[dict]:
    try:
        base = quarantine_root(root)
    except Exception:
        return None
    target = os.path.abspath(original)
    for manifest in base.glob("*.manifest.json"):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("status") == "restored":
            continue
        if os.path.abspath(str(data.get("original_path") or "")) == target:
            return data
    return None


def quarantine_move(path: str, *, active: bool = False,
                    scope_check: Optional[Callable[[str], bool]] = None,
                    root: Optional[str] = None) -> ActionResult:
    """Verschiebt eine reguläre Datei in die Quarantäne. Löscht sie nicht."""
    action = "quarantine-move"
    if not active:
        return _denied(action, "BLOCKIERT (default-deny): Quarantäne ohne Oversight. Nichts verschoben.")
    if scope_check is None:
        return _denied(action, "BLOCKIERT (default-deny): kein Scope-Check.")
    abs_p = os.path.abspath(path)
    if not (_in_scope(abs_p, scope_check) or _in_scope(path, scope_check)):
        return _denied(action, f"BLOCKIERT (default-deny): {abs_p} ist out-of-scope.",
                       {"path": abs_p})
    if os.path.islink(abs_p):
        return _denied(action, "Symlink wird nicht gefolgt und nicht verschoben.", {"path": abs_p})
    if _under_protected(abs_p):
        return _denied(action, "Systempfad wird nicht in Quarantäne verschoben.", {"path": abs_p})
    if not os.path.isfile(abs_p):
        return ActionResult(ok=False, applied=False, status="failed", action=action,
                            reason="Keine reguläre Datei.", evidence={"path": abs_p})
    try:
        qroot = quarantine_root(root)
    except Exception as exc:
        return ActionResult(ok=False, applied=False, status="failed", action=action,
                            reason=str(exc), evidence={"path": abs_p})
    real_root = str(qroot)
    if os.path.realpath(abs_p) == real_root or os.path.realpath(abs_p).startswith(real_root + os.sep):
        return _denied(action, "Datei liegt bereits in der Quarantäne.", {"path": abs_p})

    _notice()
    from .avscan import file_sha256
    try:
        digest = file_sha256(abs_p)
        mode = stat.S_IMODE(os.lstat(abs_p).st_mode)
        mtime = os.path.getmtime(abs_p)
    except OSError as exc:
        return ActionResult(ok=False, applied=False, status="failed", action=action,
                            reason=f"Datei nicht lesbar: {type(exc).__name__}",
                            evidence={"path": abs_p})

    item_id = uuid.uuid4().hex
    dest = qroot / f"{item_id}.bin"
    manifest = {
        "id": item_id,
        "original_path": abs_p,
        "quarantine_path": str(dest),
        "sha256": digest,
        "mode": mode,
        "mtime": mtime,
        "moved_at": time.time(),
        "reversible": True,
        "action": action,
        "status": "moving",
        "what_we_do": "shutil.move in kontrolliertes Quarantäne-Verzeichnis, kein unlink/rm.",
    }
    _write_manifest(qroot, manifest)
    try:
        shutil.move(abs_p, dest)
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["error"] = type(exc).__name__
        _write_manifest(qroot, manifest)
        return ActionResult(ok=False, applied=False, status="failed", action=action,
                            reason=f"Verschieben fehlgeschlagen: {type(exc).__name__}",
                            evidence=manifest)
    try:
        os.chmod(dest, 0o600)
        moved_hash = file_sha256(dest)
    except OSError:
        moved_hash = ""
    hash_ok = moved_hash == digest and bool(digest)
    manifest["status"] = "quarantined" if hash_ok else "hash_mismatch"
    manifest["sha256_after"] = moved_hash
    _write_manifest(qroot, manifest)
    if not hash_ok:
        return ActionResult(
            ok=False, applied=True, status="failed", action=action, reversible=True,
            reason="Datei verschoben, Hash weicht ab. Nicht als sauber gewertet.",
            evidence=manifest,
        )
    recheck = recheck_original(abs_p, scope_check=scope_check, root=str(qroot))
    return ActionResult(
        ok=True, applied=True, status="applied", action=action, reversible=True,
        verified=bool(recheck.get("closed")), closed=bool(recheck.get("closed")),
        reason=("In Quarantäne verschoben (kein Löschen). Originalpfad leer, "
                "Hash im Manifest bestätigt."),
        evidence={"manifest": manifest, "recheck": recheck,
                  "rollback": "restore_file", "what_we_do": manifest["what_we_do"]},
    )


def recheck_original(original: str, *, scope_check: Optional[Callable[[str], bool]] = None,
                     root: Optional[str] = None,
                     runner=None, engine: Optional[str] = None) -> dict:
    """Nachkontrolle: GESCHLOSSEN nur mit Beleg.

    * Datei noch da: erneuter ClamAV-Scan, closed nur bei verdict clean.
      Fehlt der Scanner, closed false (nicht als clean behaupten).
    * Datei weg: closed nur wenn ein Manifest denselben SHA-256 am
      Quarantänepfad belegt. Bloßes Fehlen (Löschen) schließt nicht.
    """
    from . import avscan
    abs_p = os.path.abspath(original) if original else ""
    manifest = find_manifest_for(abs_p, root) if abs_p else None
    before = {
        "path": abs_p,
        "sha256": (manifest or {}).get("sha256", ""),
        "present_before_move": True if manifest else None,
    }
    if abs_p and os.path.isfile(abs_p) and not os.path.islink(abs_p):
        scanned = avscan.recheck_path(abs_p, scope_check=scope_check, runner=runner, engine=engine)
        scanned["manifest"] = {"id": manifest.get("id")} if manifest else None
        return scanned
    if not manifest:
        return {
            "closed": False, "status": "missing_without_quarantine",
            "reason": "Pfad leer ohne Quarantäne-Manifest. Nicht als geschlossen gewertet.",
            "before": before, "after": {"path": abs_p, "present": False},
        }
    qpath = str(manifest.get("quarantine_path") or "")
    digest = ""
    try:
        if qpath and os.path.isfile(qpath):
            digest = avscan.file_sha256(qpath)
    except OSError:
        digest = ""
    hash_ok = bool(digest) and digest == manifest.get("sha256")
    av_note = None
    if hash_ok and (engine or avscan.which_engine() or runner is not None):
        def _qscope(asset: str) -> bool:
            real = os.path.realpath(asset)
            return real == os.path.realpath(qpath)
        try:
            av_note = avscan.scan_paths([qpath], scope_check=_qscope, runner=runner, engine=engine).to_dict()
        except Exception as exc:
            av_note = {"status": "error", "reason": type(exc).__name__}
    closed = hash_ok
    return {
        "closed": closed,
        "status": "GESCHLOSSEN" if closed else "unverified",
        "reason": ("Originalpfad leer, Inhalt mit gleichem SHA-256 in der Quarantäne."
                   if closed else "Quarantäne-Beleg unvollständig."),
        "before": before,
        "after": {
            "path": abs_p, "present": False, "quarantine_path": qpath,
            "sha256": digest, "hash_match": hash_ok,
            "av_on_quarantine_copy": av_note,
        },
    }


def restore_file(item_id: str, *, active: bool = False,
                 scope_check: Optional[Callable[[str], bool]] = None,
                 root: Optional[str] = None) -> ActionResult:
    """Holt eine quarantänisierte Datei zurück. Überschreibt nichts."""
    action = "quarantine-restore"
    if not active:
        return _denied(action, "BLOCKIERT (default-deny): Restore ohne Oversight.")
    if scope_check is None:
        return _denied(action, "BLOCKIERT (default-deny): kein Scope-Check.")
    try:
        base = quarantine_root(root)
    except Exception as exc:
        return ActionResult(ok=False, applied=False, status="failed", action=action, reason=str(exc))
    manifest_path = base / f"{item_id}.manifest.json"
    if not manifest_path.is_file():
        return ActionResult(ok=False, applied=False, status="failed", action=action,
                            reason="Manifest nicht gefunden.", evidence={"id": item_id})
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return ActionResult(ok=False, applied=False, status="failed", action=action,
                            reason=type(exc).__name__)
    original = str(manifest.get("original_path") or "")
    qpath = str(manifest.get("quarantine_path") or "")
    if not _in_scope(original, scope_check):
        return _denied(action, "Originalpfad out-of-scope.", {"path": original})
    if os.path.lexists(original):
        return ActionResult(ok=False, applied=False, status="failed", action=action,
                            reason="Originalpfad ist belegt. Nichts überschrieben.",
                            evidence={"path": original})
    if not os.path.isfile(qpath):
        return ActionResult(ok=False, applied=False, status="failed", action=action,
                            reason="Quarantäne-Datei fehlt.", evidence=manifest)
    _notice()
    parent = os.path.dirname(original)
    try:
        os.makedirs(parent, exist_ok=True)
        shutil.move(qpath, original)
        mode = int(manifest.get("mode") or 0o600) & 0o777
        os.chmod(original, mode)
    except OSError as exc:
        return ActionResult(ok=False, applied=False, status="failed", action=action,
                            reason=f"Restore fehlgeschlagen: {type(exc).__name__}",
                            evidence=manifest)
    manifest["status"] = "restored"
    manifest["restored_at"] = time.time()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return ActionResult(
        ok=True, applied=True, status="applied", action=action, reversible=True, verified=True,
        reason="Datei aus der Quarantäne zurückgeholt.",
        evidence={"manifest": manifest, "path": original},
    )


def _parse_ip(source: str) -> tuple[Optional[str], str]:
    try:
        ip = ipaddress.ip_address((source or "").strip())
    except ValueError:
        return None, "Quelle ist keine einzelne IP. Keine Isolation."
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return None, f"{ip} wird nicht isoliert (Loopback/Unspecified/Multicast/reserviert)."
    return str(ip), ""


def _call_runner(runner, cmd: list[str]) -> str:
    try:
        out = runner(cmd, None)
    except TypeError:
        out = runner(cmd)
    return "" if out is None else str(out)


def _system_runner(cmd: list[str], input_text: Optional[str] = None) -> str:
    del input_text
    argv = list(cmd)
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        argv = ["sudo", "-n", *argv]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    except Exception as exc:
        raise RuntimeError(type(exc).__name__) from exc
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode:
        raise RuntimeError(f"{argv[0]} fehlgeschlagen ({proc.returncode}): {output[-500:]}")
    return output


def ufw_present() -> bool:
    return shutil.which("ufw") is not None


def _ufw_ready(runner, ufw_installed: Optional[bool]) -> bool:
    """Ein injizierter Runner ist das Backend der Tests. Sonst zählt `which ufw`."""
    if ufw_installed is False:
        return False
    if ufw_installed is True:
        return True
    if runner is not None:
        return True
    return ufw_present()


def _rule_visible(status_text: str, ip: str) -> bool:
    if ip not in (status_text or ""):
        return False
    return "DENY" in status_text.upper() or "REJECT" in status_text.upper()


def isolate_source(source: str, *, active: bool = False,
                   scope_check: Optional[Callable[[str], bool]] = None,
                   runner=None, ufw_installed: Optional[bool] = None) -> ActionResult:
    """Sperrt genau eine IP per ufw, wenn ufw da ist. Sonst ehrlich unavailable."""
    action = "isolate-ufw-deny"
    ip, why = _parse_ip(source)
    if ip is None:
        return ActionResult(ok=False, applied=False, status="skipped", action=action,
                            reason=why, evidence={"source": source})
    if not active:
        return _denied(action, "BLOCKIERT (default-deny): Isolation ohne Oversight. Keine Regel gesetzt.",
                       {"source": ip})
    if not _in_scope(ip, scope_check):
        return _denied(action, f"BLOCKIERT (default-deny): {ip} ist out-of-scope.",
                       {"source": ip})
    present = _ufw_ready(runner, ufw_installed)
    intended = ["ufw", "insert", "1", "deny", "from", ip]
    rollback = ["ufw", "delete", "deny", "from", ip]
    if not present:
        return ActionResult(
            ok=True, applied=False, status="unavailable", action=action,
            reason="ufw ist nicht installiert. Keine Regel gesetzt, nichts als isoliert behauptet.",
            evidence={"source": ip, "intended_command": intended, "rollback": rollback,
                      "what_we_do": "Nur ufw-deny für eine IP. Ohne ufw kein Ersatz-Backend."},
        )
    run = runner or _system_runner
    _notice()
    evidence = {"source": ip, "intended_command": intended, "rollback": rollback,
                "what_we_do": "ufw insert 1 deny from <IP>, Prüfung über ufw status."}
    try:
        before = _call_runner(run, ["ufw", "status"])
        evidence["before"] = before[-1500:]
        _call_runner(run, intended)
        after = _call_runner(run, ["ufw", "status"])
        evidence["after"] = after[-1500:]
    except Exception as exc:
        evidence["error"] = str(exc)[:500]
        return ActionResult(ok=False, applied=False, status="failed", action=action,
                            reversible=True, reason=f"ufw-Aufruf fehlgeschlagen: {exc}",
                            evidence=evidence)
    verified = _rule_visible(evidence["after"], ip)
    return ActionResult(
        ok=True, applied=True, status="applied" if verified else "unverified",
        action=action, reversible=True, verified=verified, closed=verified,
        reason=("ufw-deny gesetzt und im Status sichtbar." if verified
                else "ufw-Befehl lief, die Regel ist im Status nicht bestätigt."),
        evidence=evidence,
    )


def release_isolation(source: str, *, active: bool = False,
                      scope_check: Optional[Callable[[str], bool]] = None,
                      runner=None, ufw_installed: Optional[bool] = None) -> ActionResult:
    """Nimmt die ufw-deny-Regel für eine IP zurück."""
    action = "isolate-ufw-release"
    ip, why = _parse_ip(source)
    if ip is None:
        return ActionResult(ok=False, applied=False, status="skipped", action=action, reason=why)
    if not active:
        return _denied(action, "BLOCKIERT (default-deny): Freigabe der Isolation ohne Oversight.")
    if not _in_scope(ip, scope_check):
        return _denied(action, f"BLOCKIERT (default-deny): {ip} ist out-of-scope.")
    present = _ufw_ready(runner, ufw_installed)
    cmd = ["ufw", "delete", "deny", "from", ip]
    if not present:
        return ActionResult(ok=True, applied=False, status="unavailable", action=action,
                            reason="ufw fehlt. Nichts zurückgenommen.",
                            evidence={"source": ip, "intended_command": cmd})
    run = runner or _system_runner
    _notice()
    try:
        before = _call_runner(run, ["ufw", "status"])
        _call_runner(run, cmd)
        after = _call_runner(run, ["ufw", "status"])
    except Exception as exc:
        return ActionResult(ok=False, applied=False, status="failed", action=action,
                            reason=str(exc), evidence={"source": ip})
    gone = ip not in after or "DENY" not in after.upper()
    return ActionResult(
        ok=True, applied=True, status="applied" if gone else "unverified",
        action=action, reversible=True, verified=gone, closed=gone,
        reason="ufw-deny zurückgenommen." if gone else "Regel nach delete noch sichtbar.",
        evidence={"source": ip, "before": before[-1500:], "after": after[-1500:], "command": cmd},
    )
