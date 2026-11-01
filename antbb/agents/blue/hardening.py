"""Blue-Soldat: Hardening-Audit und reversibles Apply.

Der Audit bleibt lesend. In der Phase `harden` werden mit Oversight und
Scope die bereits kodierten Schritte angewandt (SSH PasswordAuthentication,
sysctl, Firewall-Bind auf riskante Wildcard-Ports) und danach neu geprüft.
Ohne Freigabe wird nichts verändert.
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import hardening as _hd
from ... import hardening_apply as _ha
from ...active_oversight import ACTIVE_LEGAL_NOTICE


class HardeningAnt(BlueAgent):
    name = "blue-hardening"
    specialty = "blue-hardening-engineer"
    role = ("System-/Dienst-Härtung (CIS-artig, read-only): sichere Configs "
            "prüfen und konkrete Fix-Empfehlungen geben. Fix-Apply nur gated.")
    blue_phases = ("assess", "harden")
    playbooks = (
        Playbook("hardening-audit", "defensive", False,
                 ["ssh-config-review", "firewall-status", "world-writable-scan",
                  "sysctl-hardening"],
                 "Read-only CIS-artige Prüfung (SSH, Firewall, Dateirechte, "
                 "Kernel-sysctl) mit Fix-Empfehlung je Befund."),
        Playbook("hardening-apply", "defensive", True,
                 ["apply-recommended-fix"],
                 "SSH-Passwortlogin, sysctl und Firewall-Bind reversibel "
                 "anwenden – nur mit Oversight und Scope, danach Re-Check.",
                 tasks=["Oversight und Scope prüfen",
                        "PasswordAuthentication no (Drop-in, mit Backup)",
                        "sysctl-Drop-in setzen",
                        "Riskante Ports per ufw an localhost binden",
                        "Re-Check: GESCHLOSSEN nur bei pass"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log("[blue-hardening] 🛡 Read-only Hardening-Audit (CIS-artig).")
        results = _hd.run_audit()
        n_fail = sum(1 for r in results if r.status == "fail")
        self.ctx.log(f"[blue-hardening] {len(results)} Check(s), {n_fail} Abweichung(en).")

        _sev = {"high": "high", "medium": "medium", "low": "low"}
        for r in results:
            if r.status == "pass":
                sev, status, cat = "info", "BESTÄTIGT(PASSIV)", "blue-hardening-pass"
            elif r.status == "fail":
                sev = _sev.get(r.severity, "low")
                status, cat = "BESTÄTIGT(PASSIV)", "blue-hardening-gap"
            else:
                sev, status, cat = "info", "REFERENZ", "blue-hardening-na"
            ev = {"check_id": r.check_id, "check_status": r.status,
                  "recommendation": r.recommendation,
                  "fix_command": r.fix_command}
            ev.update(r.evidence or {})
            findings.append(AgentFinding(
                agent=self.name,
                title=f"[{r.status.upper()}] {r.title}",
                category=cat, severity=sev, asset="localhost",
                description=(r.detail + (f" · Empfehlung: {r.recommendation}"
                                          if r.recommendation else "")),
                evidence=ev, status=status,
                dedup_key=f"blue-hardening:{r.check_id}",
            ))

        if task.phase != "harden" or not self.playbook_enabled("hardening-apply"):
            return findings
        if not self.active_allowed():
            self.ctx.log("[blue-hardening] Fix-Apply nicht ausgeführt "
                         "(Oversight fehlt, default-deny).")
            return findings
        params = task.params or {}
        runner = params.get("remediation_runner")
        recheck = params.get("remediation_recheck")
        self.ctx.log(f"⚖ {ACTIVE_LEGAL_NOTICE}")
        actions = _ha.apply_reversible(
            results, active=True, scope_check=self.ctx.scope_check,
            runner=runner if callable(runner) else None,
            recheck=recheck if callable(recheck) else None,
            params={k: v for k, v in params.items()
                    if k not in ("remediation_runner", "remediation_recheck")},
        )
        for action in actions:
            closed = bool(action.get("closed"))
            check_id = action.get("check_id")
            if closed:
                for finding in findings:
                    ev = finding.evidence or {}
                    if ev.get("check_id") == check_id and finding.category == "blue-hardening-gap":
                        finding.status = "GESCHLOSSEN"
                        finding.category = "blue-remediation-verified"
                        finding.severity = "info"
                        finding.title = "[GESCHLOSSEN] " + finding.title
                        ev["before"] = "fail"
                        ev["after"] = action.get("evidence")
                        ev["closed"] = True
                        ev["commands"] = action.get("commands")
                        ev["backups"] = action.get("backups")
            findings.append(AgentFinding(
                agent=self.name,
                title=f"[{action.get('status')}] Härtung {check_id}",
                category="blue-remediation-verified" if closed else "blue-hardening-apply",
                severity="info", asset="localhost",
                description=action.get("reason") or "",
                evidence=action.get("evidence") or {"check_id": check_id, "closed": closed},
                status="GESCHLOSSEN" if closed else (
                    "REFERENZ" if action.get("status") == "denied" else "ZU BESTÄTIGEN"),
                dedup_key=f"blue-hardening-apply:{check_id}",
            ))
            self.ctx.log(f"[blue-hardening] Apply {check_id}: {action.get('status')}")
        return findings
