"""Basis für Blue-Team-Soldaten (Verteidigungs-Kolonie der Blue Queen).

Blue-Soldaten nutzen DASSELBE Interface wie die offensiven Ameisen
(`AntAgent`, `Task`, `AgentFinding`, `Playbook`) und dieselbe Registry/GUI-
Karten-Logik. Unterschiede:
  * `colony = "blue"` (für Registry/GUI-Trennung offensiv vs. defensiv).
  * `blue_phases` statt der offensiven Kill-Chain-Phasen:
    assess → watch → harden → defend → remediate → verify.
  * Default rein lesend/non-destruktiv. Aktive Fixes/Starts laufen NUR über
    das bestehende Oversight-Gate (ctx.active == Freigabe für aktive Aktion).
"""
from __future__ import annotations

from ..base import AntAgent, AgentContext, AgentFinding, Playbook, Task

#: Phasen der defensiven Kolonie (analog zur offensiven Kill-Chain).
BLUE_PHASES = ("assess", "watch", "harden", "defend", "remediate", "verify")


class BlueAgent(AntAgent):
    """Abstrakte Basis-Ameise der Verteidigungs-Kolonie."""

    colony = "blue"
    #: Blue-Team-Phasen, für die dieser Soldat zuständig ist.
    blue_phases: tuple[str, ...] = ()
    #: Die offensive `phases`-Eigenschaft bleibt leer – Blue-Soldaten werden
    #: NIE von der offensiven Königin dispatcht (getrennte Roster).
    phases: tuple[str, ...] = ()

    @classmethod
    def describe(cls) -> dict:
        d = super().describe()
        d["colony"] = "blue"
        d["blue_phases"] = list(cls.blue_phases)
        return d

    def active_allowed(self) -> bool:
        """True, wenn aktive/verändernde Aktionen freigegeben sind (Oversight)."""
        return bool(getattr(self.ctx, "active", False))

    # ---- gemeinsame Domänen-Logik der erweiterten Blue-Soldaten ----
    #: domain-Name in antbb.blue_checks.RUNNERS (leer = kein Domänen-Soldat)
    domain: str = ""
    #: playbook-name -> Check-IDs, die dieses Playbook verantwortet
    playbook_checks: dict = {}

    def runs_in(self, task: Task) -> bool:
        """Mehrphasige Soldaten arbeiten nur in ihrer ersten Phase (kein Doppel-Lauf)."""
        return bool(self.blue_phases) and task.phase == self.blue_phases[0]

    async def run_domain(self, task: Task) -> list[AgentFinding]:
        """Führt die Domänen-Checks (rein lesend) aus und wandelt sie in Findings.

        Playbooks, die per Soldaten-Override deaktiviert sind, werden ausgelassen.
        """
        from ... import blue_checks as bc
        if not self.runs_in(task):
            return []
        results = bc.RUNNERS[self.domain]()
        active_ids: set[str] = set()
        for pb, ids in self.playbook_checks.items():
            if self.playbook_enabled(pb):
                active_ids.update(ids)
            else:
                self.ctx.log(f"[{self.name}] ⏸ Playbook '{pb}' deaktiviert – übersprungen.")
        n_fail = 0
        out: list[AgentFinding] = []
        for r in results:
            if self.playbook_checks and r.check_id not in active_ids:
                continue
            if r.status == "pass":
                sev, status, cat = "info", "BESTÄTIGT(PASSIV)", f"blue-{self.domain}-pass"
            elif r.status == "fail":
                n_fail += 1
                sev, status, cat = (r.severity if r.severity in ("low", "medium", "high")
                                    else "low"), "BESTÄTIGT(PASSIV)", f"blue-{self.domain}-gap"
            else:
                sev, status, cat = "info", "REFERENZ", f"blue-{self.domain}-na"
            ev = {"check_id": r.check_id, "check_status": r.status,
                  "recommendation": r.recommendation, "fix_command": r.fix_command,
                  "domain": self.domain}
            ev.update(r.evidence or {})
            out.append(AgentFinding(
                agent=self.name, title=f"[{r.status.upper()}] {r.title}",
                category=cat, severity=sev, asset="localhost",
                description=(r.detail + (f" · Empfehlung: {r.recommendation}"
                                         if r.recommendation else "")),
                evidence=ev, status=status,
                dedup_key=f"blue-{self.domain}:{r.check_id}"))
        self.ctx.log(f"[{self.name}] {len(out)} Check(s), {n_fail} Abweichung(en).")
        return out


__all__ = ["BlueAgent", "BLUE_PHASES", "AgentContext", "AgentFinding",
           "Playbook", "Task"]
