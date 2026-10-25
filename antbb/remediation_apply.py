"""Echte Blue-Remediation hinter Oversight, ohne Shell-Eingaben aus der API.

Jede Aktion ist fest kodiert, legt bei bestehenden Konfigurationen ein Backup an
und endet in einem erneuten IST-Check. Der Standard-Runner nutzt `sudo -n`;
fehlende Rechte werden als ehrlicher Fehler statt als Erfolg gemeldet.
"""
from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timezone
from typing import Callable

from . import remediation

Runner = Callable[[list[str], str | None], str]
SUPPORTED = frozenset({
    "risky-ports-exposed", "patch-reboot-required", "ssh-password-auth",
    "sysctl-hardening", "auditd-running", "ip-forwarding", "log-forwarding",
    "login-throttling", "password-aging", "patch-auto-security",
})


class RemediationError(RuntimeError):
    """Eine Aktion ist unzulässig oder technisch fehlgeschlagen."""


def _direct_runner(command: list[str], input_text: str | None = None) -> str:
    try:
        proc = subprocess.run(
            command, input=input_text, capture_output=True,
            text=True, timeout=180, check=False,
        )
    except Exception as exc:
        raise RemediationError(f"Aufruf fehlgeschlagen: {type(exc).__name__}") from exc
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode:
        raise RemediationError(f"{command[0]} fehlgeschlagen ({proc.returncode}): {output[-800:]}")
    return output


def _sudo_runner(command: list[str], input_text: str | None = None) -> str:
    try:
        proc = subprocess.run(
            ["sudo", "-n", *command], input=input_text, capture_output=True,
            text=True, timeout=180, check=False,
        )
    except Exception as exc:
        raise RemediationError(f"Privilegierter Aufruf fehlgeschlagen: {type(exc).__name__}") from exc
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode:
        raise RemediationError(f"{command[0]} fehlgeschlagen ({proc.returncode}): {output[-800:]}")
    return output


def _default_runner() -> Runner:
    """Als Root direkt ausführen; sonst über sudo -n."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        return _direct_runner
    return _sudo_runner


def apply_fix(
    finding: dict,
    params: dict,
    *,
    runner: Runner | None = None,
    recheck: Callable[[dict], object] | None = None,
) -> dict:
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, str):
        evidence = {}
    check_id = str(evidence.get("check_id") or "")
    if check_id not in SUPPORTED:
        raise RemediationError(f"Check '{check_id or 'unbekannt'}' wird nicht unterstützt.")
    if check_id == "ip-forwarding" and not params.get("confirm_router"):
        raise RemediationError("Router-Host-Warnung: Deaktivierung muss ausdrücklich bestätigt werden.")
    if check_id == "patch-reboot-required" and not params.get("confirm_reboot"):
        raise RemediationError("Neustart muss ausdrücklich bestätigt und geplant werden.")
    if check_id == "log-forwarding" and not params.get("log_target"):
        raise RemediationError("Syslog-Ziel ist erforderlich.")

    run = runner or _default_runner()
    commands: list[str] = []
    backups: list[str] = []

    def execute(command: list[str], input_text: str | None = None) -> str:
        commands.append(" ".join(command))
        return run(command, input_text=input_text)

    def backup(path: str) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        target = f"{path}.bak-antbb-{stamp}"
        execute(["cp", "-a", path, target])
        backups.append(target)

    def write(path: str, content: str) -> None:
        execute(["tee", path], input_text=content)
        execute(["chmod", "0644", path])

    if check_id == "risky-ports-exposed":
        ports = sorted({int(p) for p in evidence.get("ports", []) if 0 < int(p) < 65536})
        if not ports:
            raise RemediationError("Keine betroffenen Ports im Befundbeleg.")
        backup("/etc/ufw/ufw.conf")
        for port in ports:
            execute(["ufw", "insert", "1", "allow", "from", "127.0.0.1", "to", "any", "port", str(port), "proto", "tcp"])
            execute(["ufw", "insert", "2", "deny", str(port) + "/tcp"])
    elif check_id == "patch-reboot-required":
        schedule = str(params.get("schedule") or "01:00").strip()
        if schedule.startswith("-") or not re.fullmatch(r"[A-Za-z0-9:+*\/,@ .-]{1,80}", schedule):
            raise RemediationError("Ungültiger Neustart-Zeitplan.")
        execute(["systemd-run", "--on-calendar", schedule, "--unit", "antbb-remediation-reboot", "/usr/bin/systemctl", "reboot"])
        return {
            "closed": False, "scheduled": True, "commands": commands, "backups": backups,
            "evidence": {"before": "fail", "after": "reboot scheduled", "schedule": schedule},
        }
    elif check_id == "ssh-password-auth":
        backup("/etc/ssh/sshd_config")
        write("/etc/ssh/sshd_config.d/99-antbb-hardening.conf", "PasswordAuthentication no\n")
        execute(["sshd", "-t"])
        execute(["systemctl", "reload", "ssh"])
    elif check_id == "sysctl-hardening":
        backup("/etc/sysctl.conf")
        write("/etc/sysctl.d/99-antbb-hardening.conf", (
            "net.ipv4.conf.all.rp_filter = 1\n"
            "net.ipv4.tcp_syncookies = 1\n"
            "net.ipv4.conf.all.accept_redirects = 0\n"
        ))
        execute(["sysctl", "--system"])
    elif check_id == "auditd-running":
        execute(["apt-get", "install", "-y", "auditd"])
        write("/etc/audit/rules.d/antbb-basic.rules", (
            "-w /etc/passwd -p wa -k identity\n"
            "-w /etc/group -p wa -k identity\n"
            "-w /etc/sudoers -p wa -k privilege\n"
            "-w /var/log/auth.log -p wa -k authentication\n"
        ))
        execute(["augenrules", "--load"])
        execute(["systemctl", "enable", "--now", "auditd"])
    elif check_id == "ip-forwarding":
        backup("/etc/sysctl.conf")
        write("/etc/sysctl.d/99-antbb-disable-forwarding.conf", "net.ipv4.ip_forward = 0\n")
        execute(["sysctl", "--system"])
    elif check_id == "log-forwarding":
        target = str(params["log_target"]).strip()
        port = int(params.get("log_port") or 514)
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", target) or not 1 <= port <= 65535:
            raise RemediationError("Ungültiges Syslog-Ziel oder ungültiger Port.")
        backup("/etc/rsyslog.conf")
        write("/etc/rsyslog.d/99-antbb-forwarding.conf", f"*.* @{target}:{port}\n")
        execute(["rsyslogd", "-N1"])
        execute(["systemctl", "restart", "rsyslog"])
    elif check_id == "login-throttling":
        execute(["apt-get", "install", "-y", "fail2ban"])
        write("/etc/fail2ban/jail.d/antbb-sshd.local", (
            "[sshd]\nenabled = true\nmaxretry = 5\nfindtime = 10m\nbantime = 30m\n"
        ))
        execute(["systemctl", "enable", "--now", "fail2ban"])
    elif check_id == "password-aging":
        backup("/etc/login.defs")
        execute(["sed", "-i", "-E", "s/^[#[:space:]]*PASS_MAX_DAYS[[:space:]]+.*/PASS_MAX_DAYS   365/", "/etc/login.defs"])
        execute(["sh", "-c", "grep -Eq '^[[:space:]]*PASS_MAX_DAYS[[:space:]]+' /etc/login.defs || printf '%s\\n' 'PASS_MAX_DAYS   365' >> /etc/login.defs"])
    elif check_id == "patch-auto-security":
        execute(["apt-get", "install", "-y", "unattended-upgrades"])
        write("/etc/apt/apt.conf.d/20auto-upgrades", (
            'APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "1";\n'
        ))
        execute(["systemctl", "enable", "--now", "unattended-upgrades"])

    if check_id == "risky-ports-exposed":
        status = execute(["ufw", "status"])
        ports = sorted({int(p) for p in evidence.get("ports", [])})
        active = "Status: active" in status or "Status: aktiv" in status
        missing = [p for p in ports if not re.search(rf"\b{p}/tcp\b[^\n]*\bDENY\b", status, re.I)]
        closed = active and not missing
        result_evidence = {"before": "fail", "after": "pass" if closed else "unverified", "ports_unverified": missing, "firewall_active": active}
        closed_value = closed
    else:
        verify = recheck or remediation.verify_closed
        step = verify(finding)
        closed_value = step.closed
        result_evidence = dict(step.evidence)

    return {
        "closed": closed_value, "scheduled": False, "commands": commands,
        "backups": backups, "evidence": result_evidence,
    }
