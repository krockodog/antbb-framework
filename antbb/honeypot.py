"""Honeypot-/Decoy-Kernmodul (Rezepte, Umleitung, echter Canary).

Leitlinien:
  * Default-deny: aktive Umleitung/Start NUR mit Oversight (active=True)
    und Scope (decoy/localhost). Ohne beides wird kein Socket geöffnet.
  * Der Canary ist low-interaction und bindet nur an Loopback: HTTP antwortet
    mit einem statischen Text, SSH sendet nur ein Banner. Kein Login, keine
    Shell, kein Cowrie-Start (Cowrie wird nicht nachinstalliert).
  * Keine Fake-Hits, keine Fake-IPs. Versuche werden lokal protokolliert.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

log = logging.getLogger("antbb.honeypot")

#: Sichere, generische Decoy-Rezepte (keine Secrets/PII, allgemeingültig).
RECIPES = [
    {"id": "ssh-decoy", "title": "SSH-Decoy (low-interaction)",
     "desc": ("Fake-SSH auf unüblichem Port, der nur Verbindungs-/Login-Versuche "
              "protokolliert (z.B. cowrie low-interaction, isoliert)."),
     "safety": "Isoliertes Netz/Container, keine echten Credentials, Logs lokal.",
     "divert_port": 2222, "protocol": "tcp"},
    {"id": "http-canary", "title": "HTTP-Canary-Endpoint",
     "desc": ("Unverlinkter Pfad/Token, dessen Abruf einen Alarm auslöst "
              "(Canarytoken-Prinzip)."),
     "safety": "Kein echter Dienst dahinter; nur Zugriffs-Logging.",
     "divert_port": 8089, "protocol": "http"},
    {"id": "decoy-file", "title": "Decoy-Dokument (Canary)",
     "desc": "Köder-Datei mit eingebettetem Canary, die beim Öffnen/Exfil meldet.",
     "safety": "Enthält keine echten Daten; rein als Tripwire.",
     "divert_port": None, "protocol": "file"},
    {"id": "smtp-decoy", "title": "SMTP-Decoy (low-interaction)",
     "desc": "Fake-SMTP der EHLO/MAIL-Versuche protokolliert, keine Relays.",
     "safety": "Kein Relay, isoliert, nur Logging.",
     "divert_port": 2525, "protocol": "tcp"},
]


@dataclass
class DivertResult:
    """Ergebnis einer Umleitungs-Entscheidung."""
    ok: bool
    applied: bool                    # True nur wenn aktive Umleitung wirklich gesetzt
    recipe_id: str = ""
    reason: str = ""
    playbook_steps: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    status: str = "skipped"          # applied | planned | denied | skipped | failed

    def to_dict(self) -> dict:
        return asdict(self)


def list_recipes() -> list[dict]:
    """Alle sicheren Rezepte (ohne Secrets)."""
    return [dict(r) for r in RECIPES]


def get_recipe(recipe_id: str) -> Optional[dict]:
    for r in RECIPES:
        if r["id"] == recipe_id:
            return dict(r)
    return None


def divert_plan(signal: dict, recipe_id: str = "http-canary") -> DivertResult:
    """Plant eine Umleitung (immer erlaubt, rein dokumentierend).

    `signal` sollte mindestens `kind` und optional `source`/`asset` enthalten.
    Liefert Playbook-Schritte; startet NICHTS.
    """
    recipe = get_recipe(recipe_id) or get_recipe("http-canary")
    assert recipe is not None
    steps = [
        f"1. Signal klassifizieren: kind={signal.get('kind', '?')} "
        f"source={signal.get('source', '?')}",
        f"2. Decoy wählen: {recipe['id']} ({recipe['title']})",
        "3. Angreifer-Traffic auf Decoy umleiten (Proxy/Firewall-Regel) – "
        "NUR mit Oversight",
        "4. Echte Assets isolieren / rate-limiten (Sofortschutz)",
        "5. Alles im Attack-Log dokumentieren (Vorher/Nachher)",
        "6. Attribution/Rückverfolgung aus echten Events starten",
    ]
    return DivertResult(
        ok=True, applied=False, recipe_id=recipe["id"],
        reason="Plan erstellt (kein aktiver Eingriff).",
        playbook_steps=steps, status="planned",
        evidence={
            "signal_kind": signal.get("kind"),
            "signal_source": signal.get("source"),
            "recipe": {"id": recipe["id"], "title": recipe["title"],
                       "protocol": recipe.get("protocol"),
                       "divert_port": recipe.get("divert_port")},
            "safety": recipe.get("safety"),
            "ts": time.time(),
        },
    )


def divert_apply(signal: dict, recipe_id: str = "http-canary", *,
                 active: bool = False,
                 apply_network: bool = False) -> DivertResult:
    """Umleitung ausführen – default-deny ohne Oversight.

    Ohne `active=True`: denied, Playbook-Schritte zurück.
    Mit Oversight: dokumentierte Umleitungsentscheidung (applied=True auf
    Steuerungsebene). Echte Netz-Regeln nur wenn zusätzlich
    `apply_network=True` UND ein unterstützter Backend vorhanden – sonst
    ehrlich als 'planned/skipped' mit Begründung.
    """
    plan = divert_plan(signal, recipe_id)
    if not active:
        plan.status = "denied"
        plan.reason = ("BLOCKIERT (default-deny): Honeypot-Umleitung ohne "
                       "Oversight-Freigabe. Nichts umgeleitet.")
        plan.applied = False
        plan.ok = False
        return plan

    # Oversight vorhanden: Steuerungsentscheidung dokumentieren.
    # Echte Netzwerkumleitung ist bewusst konservativ – ohne Backend skipped.
    evidence = dict(plan.evidence)
    evidence["oversight"] = True
    evidence["apply_network_requested"] = bool(apply_network)

    if apply_network:
        # Kein unkontrollierter iptables/nft-Call. Ehrlicher Skip mit Hinweis.
        evidence["network_backend"] = "none"
        evidence["network_note"] = (
            "Kein automatischer Netz-Backend-Call (bewusst konservativ). "
            "Operator setzt Proxy/Firewall-Regel laut Playbook-Schritten.")
        return DivertResult(
            ok=True, applied=False, recipe_id=plan.recipe_id,
            reason=("Oversight ok – Steuerungsentscheidung dokumentiert; "
                    "Netz-Backend nicht konfiguriert (skipped)."),
            playbook_steps=plan.playbook_steps, status="skipped",
            evidence=evidence,
        )

    # Steuerungsentscheidung: Umleitung als „angewendet" auf Logik-Ebene
    # (Decoy als Ziel markiert). Kein Prozess gestartet.
    evidence["divert_decision"] = "mark_decoy_target"
    evidence["decoy_marked_at"] = time.time()
    return DivertResult(
        ok=True, applied=True, recipe_id=plan.recipe_id,
        reason=("Umleitungsentscheidung gesetzt (Decoy als Ziel markiert). "
                "Kein unkontrollierter Prozess gestartet."),
        playbook_steps=plan.playbook_steps, status="applied",
        evidence=evidence,
    )


def capability_summary(active: bool = False) -> dict:
    """installed/skipped/failed-Zusammenfassung für Capability-Report."""
    live = canary_status()
    return {
        "recipes": len(RECIPES),
        "recipe_ids": [r["id"] for r in RECIPES],
        "divert_default": "deny",
        "active_oversight": bool(active),
        "network_backend": "loopback-canary" if live["running"] else "none",
        "canary": "loopback-http-ssh",
        "cowrie": "not-auto-started",
        "canary_running": live["running"],
        "status": "installed",
    }


# ---------------------------------------------------------------------------
# Low-interaction Canary (HTTP + SSH-Banner), nur Loopback, nur mit Oversight.
# ---------------------------------------------------------------------------
_CANARY_LOCK = threading.Lock()
_CANARY: dict[str, Any] = {"servers": [], "attempts": [], "log_path": "", "starting": False}
_MAX_ATTEMPTS = 200


def _canary_log_path(log_dir: Optional[str] = None) -> str:
    base = log_dir or os.path.join(os.path.expanduser("~"), ".local", "share", "antbb")
    os.makedirs(base, mode=0o700, exist_ok=True)
    path = os.path.join(base, "canary.log")
    if not os.path.exists(path):
        try:
            fd = os.open(path, os.O_CREAT | os.O_APPEND, 0o600)
            os.close(fd)
        except OSError:
            pass
    return path


def _record_attempt(kind: str, peer, line: bytes) -> None:
    text = (line or b"").split(b"\n", 1)[0][:180].decode("utf-8", "replace")
    rec = {"ts": time.time(), "kind": kind, "peer": f"{peer[0]}:{peer[1]}" if peer else "",
           "line": text}
    with _CANARY_LOCK:
        _CANARY["attempts"].append(rec)
        if len(_CANARY["attempts"]) > _MAX_ATTEMPTS:
            del _CANARY["attempts"][: len(_CANARY["attempts"]) - _MAX_ATTEMPTS]
        log_path = _CANARY.get("log_path") or ""
    if log_path:
        try:
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass


class _CanaryHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = b""
        try:
            self.request.settimeout(3.0)
            data = self.request.recv(512)
        except Exception:
            data = b""
        kind = getattr(self.server, "kind", "tcp")
        _record_attempt(kind, self.client_address, data)
        try:
            if kind == "http":
                body = b"canary\n"
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain; charset=utf-8\r\n"
                    b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
            else:
                self.request.sendall(b"SSH-2.0-antbb-canary\r\n")
        except Exception:
            pass


class _CanaryServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    kind = "http"

    def handle_error(self, request, client_address) -> None:
        return


@dataclass
class DeployResult:
    ok: bool
    applied: bool
    status: str
    reason: str
    listeners: list[dict] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def canary_status() -> dict:
    with _CANARY_LOCK:
        running = [
            {"kind": getattr(srv, "kind", ""), "port": port}
            for srv, _th, port in _CANARY["servers"]
        ]
        return {
            "running": running,
            "attempt_count": len(_CANARY["attempts"]),
            "attempts": list(_CANARY["attempts"][-20:]),
            "log_path": _CANARY.get("log_path") or "",
        }


def _scope_allows_canary(scope_check, bind: str) -> bool:
    if scope_check is None:
        return False
    for token in ("decoy", "localhost", bind, "127.0.0.1"):
        try:
            if scope_check(token):
                return True
        except Exception:
            continue
    return False


def _start_listener(kind: str, bind: str, port: int):
    srv = _CanaryServer((bind, port), _CanaryHandler)
    srv.kind = kind
    real_port = int(srv.server_address[1])
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.2},
                              name=f"antbb-canary-{kind}", daemon=True)
    thread.start()
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            with socket.create_connection((bind, real_port), timeout=0.2) as sock:
                sock.close()
            return srv, thread, real_port
        except OSError:
            time.sleep(0.02)
    try:
        srv.shutdown()
        srv.server_close()
    except Exception:
        pass
    thread.join(timeout=1)
    raise OSError(f"{kind}-Canary nimmt auf {bind}:{real_port} keine Verbindung an")


def deploy_canary(*, active: bool = False, scope_check=None,
                  bind: str = "127.0.0.1",
                  http_port: int = 8089, ssh_port: int = 2222,
                  log_dir: Optional[str] = None) -> DeployResult:
    """Startet HTTP- und SSH-Banner-Canary. Cowrie wird nicht gestartet.

    Bind nur 127.0.0.1. Ohne Oversight oder Scope: denied, kein Socket.
    """
    if not active:
        return DeployResult(
            ok=False, applied=False, status="denied",
            reason="BLOCKIERT (default-deny): Canary-Start ohne Oversight. Nichts gestartet.",
            evidence={"cowrie": "not-started"},
        )
    if bind not in ("127.0.0.1", "localhost"):
        return DeployResult(
            ok=False, applied=False, status="failed",
            reason="Canary bindet nur an 127.0.0.1 (kein 0.0.0.0, kein fremdes Interface).",
            evidence={"bind": bind, "cowrie": "not-started"},
        )
    if not _scope_allows_canary(scope_check, "127.0.0.1"):
        return DeployResult(
            ok=False, applied=False, status="denied",
            reason="BLOCKIERT (default-deny): Decoy/localhost nicht im Scope. Nichts gestartet.",
            evidence={"cowrie": "not-started"},
        )
    from .active_oversight import ACTIVE_LEGAL_NOTICE
    log.info("⚖ %s", ACTIVE_LEGAL_NOTICE)
    host = "127.0.0.1"
    with _CANARY_LOCK:
        if _CANARY["servers"] or _CANARY.get("starting"):
            listeners = [
                {"kind": getattr(srv, "kind", ""), "bind": host, "port": port}
                for srv, _th, port in _CANARY["servers"]
            ]
            return DeployResult(
                ok=True, applied=bool(_CANARY["servers"]), status="already_running",
                reason="Canary läuft bereits oder startet gerade (kein zweiter Start).",
                listeners=listeners,
                evidence={"cowrie": "not-started", "log_path": _CANARY.get("log_path") or ""},
            )
        _CANARY["starting"] = True
        try:
            _CANARY["log_path"] = _canary_log_path(log_dir)
        except OSError as exc:
            _CANARY["starting"] = False
            return DeployResult(
                ok=False, applied=False, status="failed",
                reason=f"Canary-Log nicht anlegbar: {type(exc).__name__}",
                evidence={"cowrie": "not-started"},
            )
    started = []
    errors = []
    try:
        for kind, port in (("http", int(http_port)), ("ssh", int(ssh_port))):
            try:
                srv, thread, real_port = _start_listener(kind, host, port)
            except Exception as exc:
                errors.append(f"{kind}: {type(exc).__name__}: {exc}")
                continue
            with _CANARY_LOCK:
                _CANARY["servers"].append((srv, thread, real_port))
            started.append({"kind": kind, "bind": host, "port": real_port})
    finally:
        with _CANARY_LOCK:
            _CANARY["starting"] = False
    if not started:
        return DeployResult(
            ok=False, applied=False, status="failed",
            reason="Canary nicht gestartet. " + "; ".join(errors),
            evidence={"errors": errors, "cowrie": "not-started"},
        )
    status = "applied" if not errors else "partial"
    return DeployResult(
        ok=True, applied=True, status=status,
        reason=("Low-interaction-Canary auf Loopback gestartet (HTTP-Text, SSH-Banner). "
                "Cowrie wurde nicht installiert und nicht gestartet."
                + ((" Fehler: " + "; ".join(errors)) if errors else "")),
        listeners=started,
        evidence={
            "cowrie": "not-started",
            "errors": errors,
            "log_path": canary_status()["log_path"],
            "what_we_do": "socketserver auf 127.0.0.1, kein Shell-Login, keine Credentials.",
        },
    )


def stop_canary() -> dict:
    """Stoppt laufende Canary-Listener (reversibel)."""
    with _CANARY_LOCK:
        servers = list(_CANARY["servers"])
        _CANARY["servers"] = []
        _CANARY["starting"] = False
    stopped = 0
    for srv, thread, _port in servers:
        try:
            srv.shutdown()
        except Exception:
            pass
        try:
            srv.server_close()
        except Exception:
            pass
        thread.join(timeout=2)
        stopped += 1
    return {"stopped": stopped}
