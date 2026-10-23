"""Yellow-Soldat: Probenaufnahme / Format-Klassifikation.

Nimmt eine hochgeladene Probe rein lesend auf: Groesse, SHA-256, Magic-Bytes und eine grobe Format-Klassifikation (ELF, PE, Mach-O, ZIP/APK/JAR, DEX, Klasse, PDF, Script).

Rein lesend / non-destruktiv. Tiefe oder dynamische Schritte laufen NUR ueber
das Oversight-Gate (ctx.active). Mit Erklaerpfad: zu jedem Schritt die Begruendung.
"""
from __future__ import annotations

from .base import YellowAgent, AgentFinding, Playbook, Task


_MAGIC = [
    (b"\x7fELF", "ELF (Linux/Unix-Binary)"),
    (b"MZ", "PE/DOS (Windows-Binary)"),
    (b"\xca\xfe\xba\xbe", "Mach-O FAT / Java-Class"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    (b"PK\x03\x04", "ZIP/APK/JAR/Office"),
    (b"dex\n", "DEX (Android Dalvik)"),
    (b"%PDF", "PDF"),
    (b"#!", "Script (Shebang)"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"\x89PNG", "PNG-Bild"),
]


class YellowIntakeAnt(YellowAgent):
    name = "yellow-intake"
    specialty = "yellow-intake-klassifikation"
    role = ("Probenaufnahme: hochgeladene Datei rein lesend aufnehmen, hashen und "
            "grob klassifizieren (Magic-Bytes). Startpunkt des Erklaerpfads.")
    yellow_phases = ("intake", "triage")
    playbooks = (
        Playbook("probenkarte", "defensive", False,
                 ["sha256", "size", "magic-classify"],
                 "Probenkarte anlegen: SHA-256, Groesse, Magic-Bytes und grobe "
                 "Formatklasse. Keine Ausfuehrung, nur Lesen."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        import hashlib, os
        findings: list[AgentFinding] = []
        self.ctx.log("[yellow-intake] 📥 Probenaufnahme (read-only).")
        sp = self.sample_path(task)
        if not sp:
            findings.append(AgentFinding(
                agent=self.name, title="Keine Probe uebergeben",
                category="yellow-intake", severity="info", asset="-",
                description="Erklaerpfad: Lade unter /yellow/upload eine Datei hoch "
                            "und starte den Lauf mit params.sample=<pfad>.",
                evidence={}, status="REFERENZ", dedup_key="yellow-intake:no-sample"))
            return findings
        data = open(sp, "rb").read()
        sha = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        detected = next((lbl for sig, lbl in _MAGIC if data[:len(sig)] == sig), "unbekannt")
        self.ctx.log(f"[yellow-intake] {os.path.basename(sp)}: {detected}, {len(data)} Bytes.")
        findings.append(AgentFinding(
            agent=self.name, title=f"[{detected}] {os.path.basename(sp)}",
            category="yellow-intake", severity="info", asset=os.path.basename(sp),
            description=f"Erklaerpfad: Probenkarte erstellt. Formatklasse {detected} "
                        f"bestimmt die weitere Soldaten-Kette.",
            evidence={"sha256": sha, "md5": md5, "size": len(data),
                      "magic_hex": data[:16].hex(), "detected": detected},
            status="BESTÄTIGT(PASSIV)", dedup_key=f"yellow-intake:{sha[:16]}"))
        return findings
