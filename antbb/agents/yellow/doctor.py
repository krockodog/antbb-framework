"""Yellow-Soldat: RE-Tools-Doctor.

Prueft rein lesend, welche Reverse-Engineering-Tools am Laufort verfuegbar sind (ghidra, radare2/r2, binwalk, apktool, jadx, file, strings, nm, objdump, readelf, unzip, 7z). Gibt pro Tool Status + Installationshinweis.

Rein lesend / non-destruktiv. Tiefe oder dynamische Schritte laufen NUR ueber
das Oversight-Gate (ctx.active). Mit Erklaerpfad: zu jedem Schritt die Begruendung.
"""
from __future__ import annotations

from .base import YellowAgent, AgentFinding, Playbook, Task


#: Tools, die die Gelbe Koenigin fuer statische RE nutzen kann (nur Namen).
RE_TOOLS = [
    ("file", "libmagic/file – Dateityp-Erkennung"),
    ("strings", "GNU binutils – druckbare Strings"),
    ("nm", "GNU binutils – Symboltabelle"),
    ("objdump", "GNU binutils – Disassembly/Header"),
    ("readelf", "GNU binutils – ELF-Header/Sections"),
    ("radare2", "radare2 – Analyse/Disassembly (CLI: r2)"),
    ("r2", "radare2 – Analyse/Disassembly"),
    ("rabin2", "radare2 – Binary-Info"),
    ("binwalk", "binwalk – Firmware/Container-Carving"),
    ("apktool", "apktool – APK dekodieren"),
    ("jadx", "jadx – APK/DEX nach Java"),
    ("unzip", "unzip – ZIP/APK/JAR entpacken"),
    ("7z", "p7zip – Archive"),
    ("ghidra", "Ghidra – Decompiler (headless: analyzeHeadless)"),
    ("analyzeHeadless", "Ghidra – Headless-Analyse"),
]


class YellowDoctorAnt(YellowAgent):
    name = "yellow-doctor"
    specialty = "yellow-re-tools-doctor"
    role = ("RE-Tools-Doctor: prueft rein lesend die Verfuegbarkeit der "
            "Reverse-Engineering-Werkzeuge am Laufort und gibt Installationshinweise.")
    yellow_phases = ("intake", "triage")
    playbooks = (
        Playbook("re-tools-doctor", "defensive", False,
                 ["which-scan", "version-probe"],
                 "Verfuegbarkeit der RE-Tools pruefen (shutil.which) und je Tool "
                 "einen Installationshinweis geben. Keine Ausfuehrung von Zielcode."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        import shutil
        findings: list[AgentFinding] = []
        self.ctx.log("[yellow-doctor] 🩺 RE-Tools-Doctor: pruefe Werkzeuge (read-only).")
        present, missing = [], []
        seen = set()
        for tool, hint in RE_TOOLS:
            path = shutil.which(tool)
            if path:
                present.append(tool)
                if tool not in seen:
                    findings.append(AgentFinding(
                        agent=self.name, title=f"[VORHANDEN] {tool}",
                        category="yellow-tool-ok", severity="info", asset="localhost",
                        description=f"{hint}", evidence={"path": path},
                        status="BESTÄTIGT(PASSIV)", dedup_key=f"yellow-doctor:{tool}"))
            else:
                missing.append(tool)
            seen.add(tool)
        self.ctx.log(f"[yellow-doctor] {len(present)} vorhanden, {len(missing)} fehlen.")
        if missing:
            findings.append(AgentFinding(
                agent=self.name, title=f"[HINWEIS] {len(missing)} Tool(s) fehlen",
                category="yellow-tool-missing", severity="low", asset="localhost",
                description="Erklaerpfad: fehlende Tools begrenzen die statische Analyse. "
                            "Nachinstallieren via install.sh (--yellow) oder Paketmanager.",
                evidence={"missing": missing}, status="REFERENZ",
                dedup_key="yellow-doctor:missing"))
        return findings
