"""Yellow-Soldat: ELF/Mach-O-Analyse.

Linux/Unix- und macOS-Binaries (ELF/Mach-O) rein lesend untersuchen: Header, Sections, Symbole, Imports. Disassembly nur read-only.

Rein lesend / non-destruktiv. Tiefe oder dynamische Schritte laufen NUR ueber
das Oversight-Gate (ctx.active). Mit Erklaerpfad: zu jedem Schritt die Begruendung.
"""
from __future__ import annotations

from .base import YellowAgent, AgentFinding, Playbook, Task


class YellowElfMachoAnt(YellowAgent):
    name = 'yellow-elf-macho'
    specialty = 'yellow-elf-macho-re'
    role = ('Linux/Unix- und macOS-Binaries (ELF/Mach-O) rein lesend untersuchen: Header, Sections, Symbole, Imports. Disassembly nur read-only.')
    yellow_phases = ('static', 'reconstruct')
    playbooks = (
        Playbook('elf-macho-static', 'defensive', False, ['header-parse', 'section-map', 'symbol-list', 'import-list'],
                 'ELF/Mach-O Header, Sections, Symbole und Imports rein lesend lesen (readelf/nm/objdump), Erklaerpfad je Schritt.'),
        Playbook('elf-macho-disasm', 'offensive', True, ['targeted-disasm'],
                 'Gezielte Disassembly einzelner Funktionen – nur read-only und mit Oversight.'),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        import hashlib, os
        findings: list[AgentFinding] = []
        self.ctx.log("[yellow-elf-macho] 🔎 ELF/Mach-O-Analyse (read-only).")
        sp = self.sample_path(task)
        if not sp:
            findings.append(AgentFinding(
                agent=self.name, title="Keine Probe uebergeben",
                category="yellow-intake", severity="info", asset="-",
                description="Erklaerpfad: ohne Probe keine statische Analyse. "
                            "Lade eine Datei unter /yellow/upload hoch und starte erneut.",
                evidence={"hint": "params.sample=<pfad>"}, status="REFERENZ",
                dedup_key="yellow-elf-macho:no-sample"))
            return findings
        data = open(sp, "rb").read()
        head = data[:16]
        sha = hashlib.sha256(data).hexdigest()
        magics = [(b'\x7fELF', 'ELF'), (b'\xcf\xfa\xed\xfe', 'Mach-O 64'), (b'\xfe\xed\xfa\xce', 'Mach-O 32'), (b'\xca\xfe\xba\xbe', 'Mach-O FAT')]
        detected = next((lbl for sig, lbl in magics if data[:len(sig)] == sig), "unbekannt/aus-Band")
        findings.append(AgentFinding(
            agent=self.name, title=f"[{detected}] {os.path.basename(sp)}",
            category="yellow-elf-macho", severity="info", asset=os.path.basename(sp),
            description=f"Erklaerpfad: Format anhand Magic-Bytes bestimmt ({detected}). "
                        f"Naechster Schritt gemaess Playbook, read-only.",
            evidence={"sha256": sha, "size": len(data),
                      "magic_hex": head.hex(), "detected": detected},
            status="BESTÄTIGT(PASSIV)", dedup_key=f"yellow-elf-macho:{sha[:16]}"))
        return findings
