"""Soldat dynamic: Lab-Lauf mit Oversight (Playbook dynamic-lab / frida-lab).

Yellow führt Dynamic SELBST aus, wenn gate.dynamic == yes-lab und Oversight bestätigt.
Ohne Oversight darf dieser Soldat nicht aufgerufen werden (Orchestrator blockt).
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .. import config
from ..doctor import find
from ..redact import redact
from .base import Ctx, SoldierResult, first_lines

NAME = "dynamic"


def _lab_timeout() -> int:
    try:
        return max(5, int(os.environ.get("YQ_DYNAMIC_TIMEOUT", "15")))
    except ValueError:
        return 15


def _write(ev: Path, name: str, text: str) -> str:
    p = ev / name
    p.write_text(redact(text)[:400_000], encoding="utf-8")
    return name


def run(ctx: Ctx) -> SoldierResult:
    """Führt den Lab-Pfad aus. Voraussetzung: Caller hat Oversight+yes-lab geprüft."""
    c = ctx.classification
    kind = c.get("kind", "?")
    res = SoldierResult(NAME, "dynamic-lab-re", "Dynamic-Lab-Soldat")
    res.facts["playbook"] = "dynamic-lab"
    res.facts["alt_playbook"] = "frida-lab"
    timeout = _lab_timeout()
    ran: list[str] = []
    findings_lines: list[str] = []

    plan = (
        f"Dynamic Lab Start\n"
        f"- kind: {kind}\n"
        f"- dynamic: {ctx.dynamic}\n"
        f"- timeout: {timeout}s\n"
        f"- playbook: dynamic-lab-re (+ frida-lab-re wenn Frida da)\n"
        f"- Snapshot-Hinweis: vor Prod-Runs VM-Snapshot; hier Lab-Host/ProLiant.\n"
    )
    res.evidence.append(_write(ctx.evidence_dir, "dynamic_lab_plan.txt", plan))

    # --- Linux ELF: strace / ltrace (echter kurzer Run) ---
    if kind in ("ELF", "UNKNOWN") and ctx.sample.is_file():
        strace = find(["strace"])
        if strace:
            out = ctx.evidence_dir / "dynamic_strace.txt"
            try:
                # Sample kurz unter strace laufen lassen (Lab, Oversight vorausgesetzt)
                r = subprocess.run(
                    [strace, "-f", "-tt", "-s", "120", "-o", str(out), str(ctx.sample)],
                    capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL,
                    cwd=str(ctx.evidence_dir),
                )
                # strace writes to -o file; also keep exit
                extra = ""
                if r.stdout:
                    extra += r.stdout.decode("utf-8", "replace")
                if r.stderr:
                    extra += "\n[stderr]\n" + r.stderr.decode("utf-8", "replace")
                if out.exists():
                    body = out.read_text("utf-8", "replace")
                    out.write_text(redact(body + extra)[:400_000], encoding="utf-8")
                else:
                    _write(ctx.evidence_dir, "dynamic_strace.txt", extra or f"exit={r.returncode}")
                res.tools_used.append("strace")
                res.evidence.append("dynamic_strace.txt")
                ran.append("strace")
                lines = first_lines(out.read_text("utf-8", "replace") if out.exists() else "", 20)
                findings_lines.extend(lines[:12])
                res.facts["strace_exit"] = r.returncode
                res.facts["strace_head"] = lines[:8]
            except subprocess.TimeoutExpired:
                res.status = "partial"
                ran.append("strace-timeout")
                res.tools_used.append("strace")
                if "dynamic_strace.txt" not in res.evidence:
                    res.evidence.append("dynamic_strace.txt")
                findings_lines.append(f"[Timeout nach {timeout}s – Prozess beendet]")
                res.facts["strace_timeout"] = True
            except OSError as e:
                res.status = "partial"
                res.tools_missing.append("strace-run")
                _write(ctx.evidence_dir, "dynamic_strace_error.txt", str(e))
                res.evidence.append("dynamic_strace_error.txt")
        else:
            res.tools_missing.append("strace")

        ltrace = find(["ltrace"])
        if ltrace and kind == "ELF":
            try:
                r = subprocess.run(
                    [ltrace, "-f", "-s", "80", "-o", str(ctx.evidence_dir / "dynamic_ltrace.txt"), str(ctx.sample)],
                    capture_output=True, timeout=min(timeout, 10), stdin=subprocess.DEVNULL,
                    cwd=str(ctx.evidence_dir),
                )
                p = ctx.evidence_dir / "dynamic_ltrace.txt"
                if p.exists():
                    p.write_text(redact(p.read_text("utf-8", "replace"))[:200_000], encoding="utf-8")
                    res.evidence.append("dynamic_ltrace.txt")
                    res.tools_used.append("ltrace")
                    ran.append("ltrace")
                    res.facts["ltrace_head"] = first_lines(p.read_text("utf-8", "replace"), 6)
            except (subprocess.TimeoutExpired, OSError):
                res.tools_missing.append("ltrace-run")

    # --- Frida (alle Plattformen, wenn Tool da) ---
    frida = find(["frida"])
    if frida:
        try:
            r = subprocess.run([frida, "--version"], capture_output=True, timeout=8, stdin=subprocess.DEVNULL)
            ver = (r.stdout or r.stderr or b"").decode("utf-8", "replace").strip()
            res.tools_used.append("frida")
            res.facts["frida_version"] = ver.splitlines()[0] if ver else "?"
            # Geräte/Prozesse listen (kein persistenter Hook ohne Ziel)
            ps = subprocess.run([frida, "-U", "-l", "/dev/null", "-e", "1", "2>/dev/null"] if False else [frida, "--version"],
                                capture_output=True, timeout=8, stdin=subprocess.DEVNULL)
            note = (
                f"Frida {res.facts['frida_version']} vorhanden.\n"
                f"Playbook frida-lab-re: kleiner Hook auf Lab-Device/Emulator.\n"
                f"Nächster manueller Lab-Schritt: frida -U -f <paket> -l hook.js (nur Scope).\n"
            )
            # frida-ps wenn verfügbar
            frida_ps = find(["frida-ps"]) or (str(Path(frida).with_name("frida-ps")) if Path(frida).with_name("frida-ps").exists() else None)
            if frida_ps and shutil.which(Path(frida_ps).name, path=str(Path(frida).parent) + os.pathsep + os.environ.get("PATH", "")):
                try:
                    rps = subprocess.run([frida_ps if Path(frida_ps).is_file() else "frida-ps", "-a"],
                                         capture_output=True, timeout=8, stdin=subprocess.DEVNULL)
                    ps_txt = redact((rps.stdout or b"").decode("utf-8", "replace") + (rps.stderr or b"").decode("utf-8", "replace"))
                    _write(ctx.evidence_dir, "dynamic_frida_ps.txt", ps_txt or "(keine Prozesse / kein Device)")
                    res.evidence.append("dynamic_frida_ps.txt")
                    ran.append("frida-ps")
                    res.facts["frida_ps_head"] = first_lines(ps_txt, 8)
                except (subprocess.TimeoutExpired, OSError) as e:
                    note += f"frida-ps: {type(e).__name__}\n"
            res.evidence.append(_write(ctx.evidence_dir, "dynamic_frida.txt", note))
            ran.append("frida")
        except (subprocess.TimeoutExpired, OSError) as e:
            res.tools_missing.append("frida-run")
            _write(ctx.evidence_dir, "dynamic_frida_error.txt", str(e))
            res.evidence.append("dynamic_frida_error.txt")
    else:
        res.tools_missing.append("frida")

    # --- gdb batch info (ohne full run wenn strace schon lief) ---
    if kind == "ELF" and "strace" not in ran:
        gdb = find(["gdb"])
        if gdb:
            try:
                r = subprocess.run(
                    [gdb, "-batch", "-ex", "file " + str(ctx.sample), "-ex", "info file", "-ex", "quit"],
                    capture_output=True, timeout=15, stdin=subprocess.DEVNULL,
                )
                txt = redact((r.stdout or b"").decode("utf-8", "replace") + (r.stderr or b"").decode("utf-8", "replace"))
                res.evidence.append(_write(ctx.evidence_dir, "dynamic_gdb_info.txt", txt))
                res.tools_used.append("gdb")
                ran.append("gdb-info")
                res.facts["gdb_head"] = first_lines(txt, 8)
            except (subprocess.TimeoutExpired, OSError):
                res.tools_missing.append("gdb")

    if not ran:
        res.status = "partial"
        res.warum = (
            "Dynamic mit Oversight ist freigeschaltet – Yellow startet den Lab-Pfad selbst "
            "(Playbook dynamic-lab / frida-lab). Gerade fehlen aber die Lab-CLIs (strace/frida/gdb)."
        )
        res.fund = f"Keine Lab-Tools gefunden. Fehlend: {', '.join(res.tools_missing) or 'unbekannt'}."
        res.next = ["strace/frida/gdb in YQ_TOOLS_PATH legen", "Lauf mit Oversight wiederholen"]
        res.summary_de = "Dynamic-Lab: Tools fehlen – Lauf vorbereitet, nichts ausgeführt"
        res.evidence.append(_write(ctx.evidence_dir, "dynamic_lab_missing.txt", res.fund + "\n" + "\n".join(res.tools_missing)))
        return res

    res.warum = (
        "Static allein reicht nicht für Laufzeitverhalten. Mit Oversight führe ich den Lab-Pfad selbst aus "
        "(strace/ltrace/Frida/gdb) – kurz, geloggt, Secrets geschwärzt. Alternative wäre nur Vormerken; "
        "das will Judith nicht."
    )
    res.fund = (
        f"Lab-Lauf durchgeführt mit: {', '.join(ran)}. "
        + (f"strace-Auszug: {findings_lines[0][:120]}" if findings_lines else "Siehe Evidence-Dateien dynamic_*.")
    )
    res.next = [
        "Funde mit Adresse/Syscall ins Dossier übernehmen",
        "Bei Bedarf Frida-Hook gezielt nachziehen (frida-lab)",
        "Snapshot/Lab zurücksetzen falls Detonate",
    ]
    res.facts["ran"] = ran
    res.facts["findings_head"] = findings_lines[:10]
    res.summary_de = f"Dynamic-Lab: {', '.join(ran)} · Status {res.status}"
    if res.tools_missing and res.status == "ok":
        res.status = "partial"
    return res


def blocked_result(reason: str) -> SoldierResult:
    """Wenn Dynamic angefragt aber Oversight fehlt."""
    res = SoldierResult(NAME, "dynamic-lab-re", "Dynamic-Lab-Soldat")
    res.status = "blocked"
    res.warum = "Dynamic ohne Oversight ist gesperrt – ich starte keinen Lab-Lauf."
    res.fund = reason
    res.next = ["Oversight-Checkbox setzen und Analyse erneut starten", "Oder rein statisch weiterarbeiten"]
    res.summary_de = "Dynamic-Lab: BLOCKIERT (kein Oversight)"
    return res
