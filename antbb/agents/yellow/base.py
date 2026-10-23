"""Basis für Yellow-Team-Soldaten (Reverse-Engineering-Kolonie der Gelben Königin).

Yellow-Soldaten nutzen DASSELBE Interface wie die offensiven Ameisen
(`AntAgent`, `Task`, `AgentFinding`, `Playbook`) und dieselbe Registry/GUI-
Karten-Logik. Unterschiede:
  * `colony = "yellow"` (für Registry/GUI-Trennung).
  * `yellow_phases` statt der offensiven Kill-Chain-Phasen:
    intake → triage → static → dynamic → reconstruct → dossier.
  * Default rein lesend/non-destruktiv und mit Erklärpfad: zu jedem geplanten
    Schritt gehört die Begründung, warum dieser Weg. Dynamische/tiefe Schritte
    laufen NUR über das bestehende Oversight-Gate (ctx.active).
"""
from __future__ import annotations

from ..base import AntAgent, AgentContext, AgentFinding, Playbook, Task

#: Phasen der Reverse-Engineering-Kolonie (Erklärpfad von Probe bis Dossier).
YELLOW_PHASES = ("intake", "triage", "static", "dynamic", "reconstruct", "dossier")


class YellowAgent(AntAgent):
    """Abstrakte Basis-Ameise der Reverse-Engineering-Kolonie."""

    colony = "yellow"
    #: Yellow-Team-Phasen, für die dieser Soldat zuständig ist.
    yellow_phases: tuple[str, ...] = ()
    #: Die offensive `phases`-Eigenschaft bleibt leer – Yellow-Soldaten werden
    #: NIE von der offensiven Königin dispatcht (getrennte Roster).
    phases: tuple[str, ...] = ()

    @classmethod
    def describe(cls) -> dict:
        d = super().describe()
        d["colony"] = "yellow"
        d["yellow_phases"] = list(cls.yellow_phases)
        return d

    def active_allowed(self) -> bool:
        """True, wenn tiefe/dynamische Schritte freigegeben sind (Oversight)."""
        return bool(getattr(self.ctx, "active", False))

    def sample_path(self, task: Task):
        """Pfad zur zu untersuchenden Probe aus den Task-Parametern (oder None)."""
        import os
        p = (task.params or {}).get("sample") or (task.params or {}).get("sample_path")
        if p and os.path.isfile(p):
            return p
        return None


__all__ = ["YellowAgent", "YELLOW_PHASES", "AgentContext", "AgentFinding",
           "Playbook", "Task"]
