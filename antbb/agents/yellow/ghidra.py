"""Yellow-Soldat: Ghidra-Decompile-Pipeline.

Beschreibt die read-only Ghidra-Headless-Pipeline (analyzeHeadless) fuer Decompilation. Tiefe Laeufe nur mit Oversight; keine Ausfuehrung des Zielcodes.

Rein lesend / non-destruktiv. Tiefe oder dynamische Schritte laufen NUR ueber
das Oversight-Gate (ctx.active). Mit Erklaerpfad: zu jedem Schritt die Begruendung.
"""
from __future__ import annotations

from .base import YellowAgent, AgentFinding, Playbook, Task


class YellowGhidraAnt(YellowAgent):
    name = "yellow-ghidra"
    specialty = "yellow-ghidra-pipeline"
    role = ("Ghidra-Decompile-Pipeline (headless, read-only): Projekt anlegen, "
            "Auto-Analyse, Decompilat exportieren. Tiefe Laeufe nur mit Oversight.")
    yellow_phases = ("static", "reconstruct")
    playbooks = (
        Playbook("ghidra-headless", "defensive", False,
                 ["project-create", "auto-analyze", "decompile-export"],
                 "analyzeHeadless-Projekt anlegen, Auto-Analyse, Decompilat als "
                 "C-Pseudocode exportieren. Read-only, keine Zielcode-Ausfuehrung."),
        Playbook("ghidra-deep-dive", "offensive", True,
                 ["function-deep-read"],
                 "Tiefe Funktions-Rekonstruktion – nur read-only und mit Oversight."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        import shutil
        findings: list[AgentFinding] = []
        self.ctx.log("[yellow-ghidra] 🧩 Ghidra-Pipeline (Erklaerpfad, read-only).")
        have = shutil.which("analyzeHeadless") or shutil.which("ghidra")
        findings.append(AgentFinding(
            agent=self.name,
            title=("[BEREIT] Ghidra verfuegbar" if have else "[HINWEIS] Ghidra fehlt"),
            category="yellow-ghidra", severity=("info" if have else "low"),
            asset="localhost",
            description=("Erklaerpfad: Ghidra-Headless kann genutzt werden." if have
                         else "Erklaerpfad: Ghidra nicht gefunden – via install.sh (--yellow) "
                              "oder manuell nachziehen, um Decompilation zu nutzen."),
            evidence={"analyzeHeadless": bool(have)},
            status=("BESTÄTIGT(PASSIV)" if have else "REFERENZ"),
            dedup_key="yellow-ghidra:status"))
        return findings
