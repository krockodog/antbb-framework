"""Yellow-Soldat: .NET-Analyse.

.NET-Assemblies rein lesend untersuchen: Metadaten, Typen, Methoden, IL. Kein Patching ohne Oversight.

Rein lesend / non-destruktiv. Tiefe oder dynamische Schritte laufen NUR ueber
das Oversight-Gate (ctx.active). Mit Erklaerpfad: zu jedem Schritt die Begruendung.
"""
from __future__ import annotations

from .base import YellowAgent, AgentFinding, Playbook, Task


class YellowDotnetAnt(YellowAgent):
    name = 'yellow-dotnet'
    specialty = 'yellow-dotnet-re'
    role = ('.NET-Assemblies rein lesend untersuchen: Metadaten, Typen, Methoden, IL. Kein Patching ohne Oversight.')
    yellow_phases = ('static', 'reconstruct')
    playbooks = (
        Playbook('dotnet-static', 'defensive', False, ['metadata-parse', 'type-list', 'method-overview'],
                 '.NET-Metadaten, Typen und Methoden rein lesend lesen (ILSpy/monodis-artig).'),
        Playbook('dotnet-il', 'offensive', True, ['targeted-il-read'],
                 'Gezieltes IL-Lesen einzelner Methoden – read-only, mit Oversight.'),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        import hashlib, os
        findings: list[AgentFinding] = []
        self.ctx.log("[yellow-dotnet] 🔎 .NET-Analyse (read-only).")
        sp = self.sample_path(task)
        if not sp:
            findings.append(AgentFinding(
                agent=self.name, title="Keine Probe uebergeben",
                category="yellow-intake", severity="info", asset="-",
                description="Erklaerpfad: ohne Probe keine statische Analyse. "
                            "Lade eine Datei unter /yellow/upload hoch und starte erneut.",
                evidence={"hint": "params.sample=<pfad>"}, status="REFERENZ",
                dedup_key="yellow-dotnet:no-sample"))
            return findings
        data = open(sp, "rb").read()
        head = data[:16]
        sha = hashlib.sha256(data).hexdigest()
        magics = [(b'MZ', 'PE/.NET')]
        detected = next((lbl for sig, lbl in magics if data[:len(sig)] == sig), "unbekannt/aus-Band")
        findings.append(AgentFinding(
            agent=self.name, title=f"[{detected}] {os.path.basename(sp)}",
            category="yellow-dotnet", severity="info", asset=os.path.basename(sp),
            description=f"Erklaerpfad: Format anhand Magic-Bytes bestimmt ({detected}). "
                        f"Naechster Schritt gemaess Playbook, read-only.",
            evidence={"sha256": sha, "size": len(data),
                      "magic_hex": head.hex(), "detected": detected},
            status="BESTÄTIGT(PASSIV)", dedup_key=f"yellow-dotnet:{sha[:16]}"))
        return findings
