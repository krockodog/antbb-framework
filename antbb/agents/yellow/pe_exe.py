"""Yellow-Soldat: PE/EXE-Analyse.

Windows-Binaries (PE/EXE/DLL) rein lesend untersuchen: DOS/PE-Header, Sections, Imports/Exports, Ressourcen. Keine Ausfuehrung.

Rein lesend / non-destruktiv. Tiefe oder dynamische Schritte laufen NUR ueber
das Oversight-Gate (ctx.active). Mit Erklaerpfad: zu jedem Schritt die Begruendung.
"""
from __future__ import annotations

from .base import YellowAgent, AgentFinding, Playbook, Task


class YellowPeExeAnt(YellowAgent):
    name = 'yellow-pe-exe'
    specialty = 'yellow-pe-exe-re'
    role = ('Windows-Binaries (PE/EXE/DLL) rein lesend untersuchen: DOS/PE-Header, Sections, Imports/Exports, Ressourcen. Keine Ausfuehrung.')
    yellow_phases = ('static', 'reconstruct')
    playbooks = (
        Playbook('pe-static', 'defensive', False, ['pe-header', 'section-map', 'import-export', 'resource-list'],
                 'PE-Header, Sections, Import-/Export-Tabellen und Ressourcen rein lesend lesen.'),
        Playbook('pe-disasm', 'offensive', True, ['targeted-disasm'],
                 'Gezielte Disassembly – nur read-only und mit Oversight.'),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        import hashlib, os
        findings: list[AgentFinding] = []
        self.ctx.log("[yellow-pe-exe] 🔎 PE/EXE-Analyse (read-only).")
        sp = self.sample_path(task)
        if not sp:
            findings.append(AgentFinding(
                agent=self.name, title="Keine Probe uebergeben",
                category="yellow-intake", severity="info", asset="-",
                description="Erklaerpfad: ohne Probe keine statische Analyse. "
                            "Lade eine Datei unter /yellow/upload hoch und starte erneut.",
                evidence={"hint": "params.sample=<pfad>"}, status="REFERENZ",
                dedup_key="yellow-pe-exe:no-sample"))
            return findings
        data = open(sp, "rb").read()
        head = data[:16]
        sha = hashlib.sha256(data).hexdigest()
        magics = [(b'MZ', 'PE/DOS')]
        detected = next((lbl for sig, lbl in magics if data[:len(sig)] == sig), "unbekannt/aus-Band")
        findings.append(AgentFinding(
            agent=self.name, title=f"[{detected}] {os.path.basename(sp)}",
            category="yellow-pe-exe", severity="info", asset=os.path.basename(sp),
            description=f"Erklaerpfad: Format anhand Magic-Bytes bestimmt ({detected}). "
                        f"Naechster Schritt gemaess Playbook, read-only.",
            evidence={"sha256": sha, "size": len(data),
                      "magic_hex": head.hex(), "detected": detected},
            status="BESTÄTIGT(PASSIV)", dedup_key=f"yellow-pe-exe:{sha[:16]}"))
        return findings
