"""Yellow-Soldat: APK/Android-Analyse.

Android-Apps (APK/DEX) rein lesend untersuchen: Manifest, Permissions, Klassenpfade, eingebettete .so. Secrets werden redigiert.

Rein lesend / non-destruktiv. Tiefe oder dynamische Schritte laufen NUR ueber
das Oversight-Gate (ctx.active). Mit Erklaerpfad: zu jedem Schritt die Begruendung.
"""
from __future__ import annotations

from .base import YellowAgent, AgentFinding, Playbook, Task


class YellowApkAnt(YellowAgent):
    name = 'yellow-apk'
    specialty = 'yellow-apk-android-re'
    role = ('Android-Apps (APK/DEX) rein lesend untersuchen: Manifest, Permissions, Klassenpfade, eingebettete .so. Secrets werden redigiert.')
    yellow_phases = ('static', 'reconstruct')
    playbooks = (
        Playbook('apk-static', 'defensive', False, ['manifest-extract', 'permission-list', 'class-overview', 'native-lib-list'],
                 'APK entpacken (read-only), Manifest/Permissions/Klassen/so-Dateien auflisten.'),
        Playbook('apk-secrets', 'defensive', False, ['redacted-secret-scan'],
                 'Eingebettete Secrets/URLs nur kategorisieren und redigieren – nie ausgeben.'),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        import hashlib, os
        findings: list[AgentFinding] = []
        self.ctx.log("[yellow-apk] 🔎 APK/Android-Analyse (read-only).")
        sp = self.sample_path(task)
        if not sp:
            findings.append(AgentFinding(
                agent=self.name, title="Keine Probe uebergeben",
                category="yellow-intake", severity="info", asset="-",
                description="Erklaerpfad: ohne Probe keine statische Analyse. "
                            "Lade eine Datei unter /yellow/upload hoch und starte erneut.",
                evidence={"hint": "params.sample=<pfad>"}, status="REFERENZ",
                dedup_key="yellow-apk:no-sample"))
            return findings
        data = open(sp, "rb").read()
        head = data[:16]
        sha = hashlib.sha256(data).hexdigest()
        magics = [(b'PK\x03\x04', 'ZIP/APK/JAR'), (b'dex\n', 'DEX')]
        detected = next((lbl for sig, lbl in magics if data[:len(sig)] == sig), "unbekannt/aus-Band")
        findings.append(AgentFinding(
            agent=self.name, title=f"[{detected}] {os.path.basename(sp)}",
            category="yellow-apk", severity="info", asset=os.path.basename(sp),
            description=f"Erklaerpfad: Format anhand Magic-Bytes bestimmt ({detected}). "
                        f"Naechster Schritt gemaess Playbook, read-only.",
            evidence={"sha256": sha, "size": len(data),
                      "magic_hex": head.hex(), "detected": detected},
            status="BESTÄTIGT(PASSIV)", dedup_key=f"yellow-apk:{sha[:16]}"))
        return findings
