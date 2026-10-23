"""Yellow-Soldat: RE-Ergebnis-Dossier.

Fuehrt die Befunde der Yellow-Kolonie zu einem nachvollziehbaren Dossier zusammen (Erklaerpfad, Ledger). Fasst zusammen, redigiert Secrets.

Rein lesend / non-destruktiv. Tiefe oder dynamische Schritte laufen NUR ueber
das Oversight-Gate (ctx.active). Mit Erklaerpfad: zu jedem Schritt die Begruendung.
"""
from __future__ import annotations

from .base import YellowAgent, AgentFinding, Playbook, Task


class YellowDossierAnt(YellowAgent):
    name = "yellow-dossier"
    specialty = "yellow-re-result-dossier"
    role = ("RE-Ergebnis-Dossier: Befunde der Kolonie zu einem nachvollziehbaren "
            "Dossier zusammenfassen (Erklaerpfad + Ledger), Secrets redigiert.")
    yellow_phases = ("dossier",)
    playbooks = (
        Playbook("re-dossier", "defensive", False,
                 ["collect-findings", "explain-path", "ledger-entry"],
                 "Befunde einsammeln, Erklaerpfad dokumentieren und einen "
                 "Ledger-Eintrag erzeugen. Keine Secrets im Dossier."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        prev = [f for f in (task.context_findings or []) if getattr(f, "agent", "") != self.name]
        self.ctx.log(f"[yellow-dossier] 📒 Dossier: fasse {len(prev)} Befund(e) zusammen.")
        cats = sorted({getattr(f, "category", "") for f in prev})
        return [AgentFinding(
            agent=self.name, title=f"[DOSSIER] {len(prev)} Befund(e) zusammengefuehrt",
            category="yellow-dossier", severity="info", asset="-",
            description="Erklaerpfad: Yellow-Befunde zu einem Dossier zusammengefuehrt. "
                        "Jeder Schritt bleibt im Ledger nachvollziehbar.",
            evidence={"finding_count": len(prev), "categories": cats},
            status="BESTÄTIGT(PASSIV)", dedup_key="yellow-dossier:summary")]
