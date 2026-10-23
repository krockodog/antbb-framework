---
id: yellow-queen-orchestrate
queen: yellow
title: "yellow-queen-orchestrate"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Yellow Queen Orchestrate — Decision Tree Runbook

Die Queen orchestriert **und erklärt**. Skills/Soldaten liefern Evidence; Queen merged Dossier, Ledger und Neural-Brain-Status.

## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.

## Wann
- User droppt EXE/APK/ELF/HEX/…
- „analysiere / rekonstruiere X“
- Nach Pause: Ledger Next-3 neu planen

## Phasen

### Phase 0 — Gate (+ erklären)
- Autorisierung/Scope
- Oversight-Punkte (Dynamic/Frida/Detonate)
- Erklärbär: *Warum wir noch nicht decompilieren*

### Phase 1 — Classify
```
sha256sum "$SAMPLE"
file "$SAMPLE"
# DIE; rabin2 -I
```
Erklärbär: Format/Packer/.NET-Signal in einem Satz.

### Phase 2 — Pick toolchain

| Signal | Primär | Parallel/Alt | Nicht zuerst |
|---|---|---|---|
| Packer | packer-unpack-re | DIE | Ghidra auf packed |
| .NET/CLR | dotnet-re | PE meta | Ghidra native |
| APK | apk-android-re | apkleaks | native ohne JADX-Map |
| ELF/Mach-O | elf-macho-re + r2 | Ghidra | Dynamic |
| PE native | pe-exe-re + r2 | Ghidra | |
| Firmware | hex-firmware-re | binwalk | stille wrong-base |
| MZ 16-bit | dos-mz-16bit-re | DOSBox later | 32-bit assumptions |
| Disk image | autopsy-forensics-bridge | export hashes | „RE in Autopsy“ |
| Malware smell | malware-triage-re | yara/capa | runaway detonate |

Erklärbär: *Warum Tool A vor Tool B*.

### Phase 3 — Spawn (Run-Card)
```markdown
## Run-Card
- Sample/SHA:
- Class:
- Primary skill / Alternate:
- Playbook:
- Dynamic?: no|ask|yes-lab
- Brain hop: classify→…→merge
- Deliverables: evidence/ notes/LEDGER.md dossier.md
```

### Phase 4 — Merge
- `re-result-dossier` (inkl. **Erklärung**)
- `re-progress-ledger`
- `yellow-neural-brain` Status aktualisieren

### Phase 5 — Continue
Nächste Session startet bei Ledger Next-3.

## Qualitätsbar
- Adressen + Tool-Namen + Erklärbär-Absatz
- Fakten ≠ Hypothesen
- Kein DRM/Crack

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.
