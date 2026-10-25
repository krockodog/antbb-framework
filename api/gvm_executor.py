"""Blue-GVM-Executor: echte Greenbone/GVM-Anbindung über den gvmd-Socket.

Nur allowgelistete Ziele, Oversight bleibt Pflicht (Run-Gate). Ablauf:
Version-Check → Scan-Config → Target → Task → Start → bounded Poll.
Antwortet gvmd nicht, wird das ehrlich vermerkt statt simuliert.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

SOCKET = "/run/gvmd/gvmd.sock"
CONFIG = "/home/lordix/antbb/.gvm-tools.conf"
POLL_SECONDS = 90
POLL_INTERVAL = 5


def _gvm_cli(xml: str, timeout: int = 60) -> str:
    """gvm-cli gegen den gvmd-Socket. Als Root über runuser->_gvm, weil
    gvm-cli root verweigert; Credentials kommen aus der root:_gvm-Config."""
    if not os.path.isfile(CONFIG):
        raise RuntimeError(f"GVM-Config fehlt: {CONFIG} (gmp-Zugang einrichten)")
    cmd = ["gvm-cli", "-c", CONFIG, "socket", "--socketpath", SOCKET, "--xml", xml]
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        cmd = ["runuser", "-u", "_gvm", "--"] + cmd
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"gvm-cli rc={proc.returncode}: {(proc.stderr or '')[:300]}")
    return proc.stdout or ""


def _id(xml: str, pattern: str) -> str:
    m = re.search(r"<" + pattern + r"[^>]*\bid=\"([^\"]+)\"", xml)
    return m.group(1) if m else ""


def _ok(xml: str) -> bool:
    return 'status="20' in xml


def run_gvm_scan(targets: list[str], folder: Path, transport=None,
                 poll_seconds: int = POLL_SECONDS) -> dict:
    """Führt einen echten GVM-Scan (Full and fast) gegen allowgelistete Ziele."""
    log: list[str] = []
    if not shutil.which("gvm-cli"):
        return {"ok": False, "executor": "blue-gvm", "error": "gvm-cli nicht installiert (python3-gvm)."}
    send = transport or _gvm_cli

    def call(xml: str, what: str, timeout: int = 60) -> str:
        try:
            out = send(xml, timeout)
        except Exception as exc:  # Socket/CLI-Fehler
            raise RuntimeError(f"{what} fehlgeschlagen: {type(exc).__name__}: {exc}") from exc
        log.append(f"<!-- ### {what} ### -->\n{out}")
        return out

    try:
        ver = call("<get_version/>", "get_version")
        if not _ok(ver):
            return {"ok": False, "executor": "blue-gvm", "error": "gvmd antwortet nicht auf get_version (Socket bereit?)"}

        confs = call("<get_configs/>", "get_configs")
        m = re.search(r'<config id="([^"]+)"[^>]*>\s*<name>([^<]*(?:Full and fast|Discovery)[^<]*)</name>',
                      confs)
        if not m:
            return {"ok": False, "executor": "blue-gvm", "error": "Keine passende Scan-Config in gvmd gefunden."}
        config_id, config_name = m.group(1), m.group(2)

        stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
        hosts = " ".join(targets[:10])
        tgt = call(f'<create_target><name>antbb-{stamp}</name><hosts>{hosts}</hosts></create_target>',
                   "create_target")
        target_id = _id(tgt, "create_target_response")
        if not _ok(tgt) or not target_id:
            return {"ok": False, "executor": "blue-gvm", "error": f"create_target fehlgeschlagen: {tgt[:300]}"}

        task = call(
            f'<create_task><name>antbb-{stamp}</name><config id="{config_id}"/>'
            f'<target id="{target_id}"/></create_task>', "create_task")
        task_id = _id(task, "create_task_response")
        if not _ok(task) or not task_id:
            return {"ok": False, "executor": "blue-gvm", "error": f"create_task fehlgeschlagen: {task[:300]}"}

        start = call(f'<start_task task_id="{task_id}"/>', "start_task")
        if not _ok(start):
            return {"ok": False, "executor": "blue-gvm", "error": f"start_task fehlgeschlagen: {start[:300]}"}

        deadline = time.time() + poll_seconds
        status = "Running"
        while True:
            t = call(f'<get_tasks task_id="{task_id}"/>', "get_tasks", timeout=30)
            ms = re.search(r"<status>([^<]+)</status>", t)
            status = ms.group(1) if ms else "Unknown"
            if status in ("Done", "Stopped", "Interrupted") or time.time() >= deadline:
                break
            time.sleep(POLL_INTERVAL)
    except RuntimeError as exc:
        return {"ok": False, "executor": "blue-gvm", "error": str(exc)}
    finally:
        (folder / "gvm-session.xml").write_text(
            "\n".join(log) + "\n", encoding="utf-8", errors="replace")

    findings: dict = {"executor": "blue-gvm", "ok": True, "task_id": task_id,
                      "target_id": target_id, "config": config_name,
                      "status": status, "artifacts": ["gvm-session.xml"]}
    if status == "Done":
        res = call(f'<get_results task_id="{task_id}"/>', "get_results")
        mc = re.search(r"<result_count>(\d+)</result_count>", res)
        count = int(mc.group(1)) if mc else len(re.findall(r"<result id=", res))
        findings["results"] = count
        findings["note"] = f"Scan abgeschlossen – {count} Ergebnisse (Task {task_id})."
    else:
        findings["note"] = (f"Scan gestartet (Task {task_id}, Status {status}) – "
                            "läuft im Hintergrund; Ergebnis später in GVM prüfen.")
    return findings
