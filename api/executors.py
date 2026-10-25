"""Echte Executor für Red/Blue/Yellow-Läufe — keine Dossier-Mocks mehr.

- Red:   echtes Recon via nmap (-F --version-light, XML-Artefakt im Lauf-Ordner).
- Blue:  echtes Hardening-Audit (antbb.hardening.run_audit, read-only) als Artefakt.
- Yellow: echte RE-Triage der hochgeladenen Probe (SHA-256, Magic, Strings-Auszug).

Alles scope-gebunden (Ziele kommen nur aus der geprüften Allowlist), mit
harten Zeitlimits. Fehlt ein Werkzeug, sagt der Executor das ehrlich statt
Fake-Daten zu liefern.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
from dataclasses import asdict
from pathlib import Path

from .gvm_executor import run_gvm_scan
from .tool_playbooks import CLI_TOOLS, OPERATOR_TOOLS

_MAGIC = [
    (b"MZ", "PE/EXE (Windows)"),
    (b"\x7fELF", "ELF (Linux/Unix)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O (macOS)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O (macOS)"),
    (b"PK\x03\x04", "ZIP/APK/DOCX-Container"),
    (b"\x89PNG", "PNG-Bild"),
    (b"\xff\xd8\xff", "JPEG-Bild"),
    (b"#!", "Skript (Shebang)"),
]

MAX_TARGETS = 5
RED_TIMEOUT = 90
_STRINGS_RE = re.compile(rb"[ -~]{5,}")


def _run(cmd: list[str], timeout: int, cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)


def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""


def run_red_recon(targets: list[str], folder: Path) -> dict:
    """Echtes Recon pro Ziel (max MAX_TARGETS). Nur vom Aufrufer geprüfte Ziele."""
    if not shutil.which("nmap"):
        return {"executor": "red-recon", "stub": False,
                "note": "nmap ist auf diesem Host nicht installiert – kein Recon möglich."}
    results = []
    for target in targets[:MAX_TARGETS]:
        entry: dict = {"target": target, "ip": _resolve(target)}
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
        try:
            proc = _run(["nmap", "-F", "--version-light", "--host-timeout", "20s",
                         "-oX", "-", target], RED_TIMEOUT)
        except subprocess.TimeoutExpired:
            entry["note"] = "nmap Zeitlimit überschritten"
            results.append(entry)
            continue
        except OSError as exc:
            entry["note"] = f"nmap nicht ausführbar: {type(exc).__name__} (Root?)"
            results.append(entry)
            continue
        if "<nmaprun" in (proc.stdout or ""):
            xml_name = f"nmap-{safe}.xml"
            (folder / xml_name).write_text(proc.stdout, encoding="utf-8", errors="replace")
            entry["xml_file"] = xml_name
            entry["open_ports"] = len(re.findall(r'<state state="open"', proc.stdout))
        else:
            entry["note"] = f"nmap rc={proc.returncode}: {(proc.stderr or '')[:200]}"
        results.append(entry)
    return {"executor": "red-recon", "stub": False, "results": results}


def run_blue_audit(folder: Path) -> dict:
    """Echtes, read-only Hardening-Audit aus der antbb-Engine (in-process)."""
    try:
        from antbb.hardening import run_audit
    except Exception as exc:  # Colony-Paket nicht verfügbar
        return {"executor": "blue-audit", "stub": False,
                "note": f"antbb-Hardening-Modul nicht verfügbar: {type(exc).__name__}"}
    checks = run_audit()
    payload = [asdict(c) if hasattr(c, "__dataclass_fields__") else dict(c) for c in checks]
    (folder / "hardening-audit.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    fail = sum(1 for c in payload if c.get("status") == "fail")
    return {"executor": "blue-audit", "stub": False,
            "audit_file": "hardening-audit.json",
            "checks": len(payload), "failed": fail}


def _find_upload(probe_name: str) -> Path | None:
    roots = [Path(os.environ.get("YQ_DATA", "/home/lordix/yellow-queen/data")) / "uploads",
             Path(os.environ.get("YQ_DATA", "/home/lordix/yellow-queen/data"))]
    wanted = probe_name.strip().lower()
    for root in roots:
        if not root.is_dir():
            continue
        for candidate in root.rglob("*"):
            if candidate.is_file() and candidate.name.lower() == wanted:
                return candidate
    return None


def run_yellow_triage(probe_name: str, folder: Path) -> dict:
    """Echte Triage der hochgeladenen Probe: Hash, Magic, Strings-Auszug."""
    path = _find_upload(probe_name) if probe_name else None
    if path is None:
        return {"executor": "yellow-triage", "stub": False,
                "note": f"Keine hochgeladene Probe '{probe_name}' gefunden – Triage entfällt."}
    data = path.read_bytes()
    head = data[:16]
    magic = next((label for sig, label in _MAGIC if head.startswith(sig)), "unbekannt")
    digest = hashlib.sha256(data).hexdigest()
    strings = [m.group().decode("ascii", "replace")
               for m in _STRINGS_RE.finditer(data[:65536])][:40]
    report = {
        "file": path.name, "size": len(data), "sha256": digest,
        "magic": magic, "strings_excerpt": strings,
        "note": "Nur statische Triage – nichts wurde ausgeführt.",
    }
    (folder / "triage.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"executor": "yellow-triage", "stub": False,
            "triage_file": "triage.json", "sha256": digest, "magic": magic}


def _find_tool_binary(candidates: list[str]) -> str:
    """Erste vorhandene, ausführbare Binärdatei aus den Kandidaten."""
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        if os.sep not in candidate:
            found = shutil.which(candidate)
            if found:
                return found
    return ""


def run_cli_tool(playbook_id: str, targets: list[str], folder: Path) -> dict:
    """Echtes, nicht-interaktives Tool per subprocess mit Timeout ausführen.

    stdout/stderr landen als Artefakt im Lauf-Ordner. Fehlende Binärdatei,
    Zeitlimit oder Fehlerrückgabe werden ehrlich im Dossier vermerkt.
    """
    spec = CLI_TOOLS[playbook_id]
    binary = _find_tool_binary(spec["binaries"])
    if not binary:
        return {"executor": playbook_id, "stub": False, "tool": spec["tool"],
                "note": (f"{spec['tool']} ist auf diesem Host nicht installiert "
                         f"(erwartet unter {spec['repo_path']}) – kein Lauf möglich.")}
    argv = spec["argv"](binary, targets, folder)
    try:
        proc = _run(argv, spec["timeout"], cwd=spec.get("cwd"))
    except subprocess.TimeoutExpired:
        return {"executor": playbook_id, "stub": False, "tool": spec["tool"],
                "note": f"{spec['tool']}: Zeitlimit ({spec['timeout']}s) überschritten."}
    except OSError as exc:
        return {"executor": playbook_id, "stub": False, "tool": spec["tool"],
                "note": f"{spec['tool']} nicht ausführbar: {type(exc).__name__}: {exc}"}
    artifact = f"{playbook_id}.log"
    (folder / artifact).write_text(
        f"$ {' '.join(argv)}\n\n=== stdout (rc={proc.returncode}) ===\n{proc.stdout or ''}\n"
        f"=== stderr ===\n{proc.stderr or ''}\n",
        encoding="utf-8", errors="replace")
    extra = spec.get("extra_artifact")
    if extra:
        (folder / extra[0]).write_text(extra[1], encoding="utf-8")
    note = None
    if proc.returncode != 0:
        note = (f"{spec['tool']}: rc={proc.returncode} — "
                f"{(proc.stderr or proc.stdout or '')[:200]}")
    return {"executor": playbook_id, "stub": False, "tool": spec["tool"],
            "artifact": artifact, "returncode": proc.returncode, "note": note}


def run_operator_start(playbook_id: str, targets: list[str], folder: Path) -> dict:
    """Interaktive/Docker-Tools NICHT autonom starten — Start-Artefakt ins Dossier.

    Der Operator startet das Werkzeug von Hand (Vorlage im Artefakt), oversight-pflichtig.
    """
    spec = OPERATOR_TOOLS[playbook_id]
    command = spec["start_template"].format(repo_path=spec["repo_path"])
    start_file = f"{playbook_id}-start.json"
    payload = {
        "playbook_id": playbook_id,
        "tool": spec["tool"],
        "repo_path": spec["repo_path"],
        "scope_targets": list(targets),
        "start_command": command,
        "summary": spec["summary"],
        "note": spec["note"],
        "operator_started": False,
        "oversight_required": True,
    }
    (folder / start_file).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (folder / f"{playbook_id}-start.sh").write_text(
        f"#!/bin/sh\n# {spec['tool']} — operator-gestartet, oversight-pflichtig\n"
        f"# Scope: {', '.join(targets)}\n{command}\n", encoding="utf-8")
    return {"executor": "operator-start", "stub": False, "tool": spec["tool"],
            "operator_started": False, "start_artifact": start_file,
            "note": f"operator-gestartet, oversight-pflichtig: {spec['note']}"}


def execute(queen_id: str, playbook_id: str, targets: list[str],
            probe_name: str | None, folder: Path) -> dict:
    """Führt die echte Arbeit aus; Fehler werden ehrlich im Dossier vermerkt."""
    try:
        if queen_id == "red":
            if playbook_id in CLI_TOOLS:
                return run_cli_tool(playbook_id, targets, folder)
            if playbook_id in OPERATOR_TOOLS:
                return run_operator_start(playbook_id, targets, folder)
            return run_red_recon(targets, folder)
        if queen_id == "blue":
            if playbook_id in CLI_TOOLS:
                return run_cli_tool(playbook_id, targets, folder)
            if playbook_id in OPERATOR_TOOLS:
                return run_operator_start(playbook_id, targets, folder)
            if "greenbone" in playbook_id.lower():
                return run_gvm_scan(targets, folder)
            return run_blue_audit(folder)
        if queen_id == "yellow":
            return run_yellow_triage(probe_name or "", folder)
        return {"executor": "none", "stub": False, "note": f"Kein Executor für {queen_id}."}
    except Exception as exc:  # niemals den Lauf crashen lassen
        return {"executor": "error", "stub": False,
                "note": f"Executor-Fehler: {type(exc).__name__}: {exc}"}
