---
id: re-tooling-setup
queen: yellow
title: "re-tooling-setup"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# RE Tooling Setup — Multi-Tool Doctor

Wie ein „rea doctor“, aber für den **ganzen** Stack — nicht nur Ghidra.


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Checkliste (OK / FEHLT / VERSION)

### Core triage
- [ ] `file`, `sha256sum`/`shasum`
- [ ] Detect It Easy (DIE) oder CLI-Äquivalent
- [ ] `strings` + floss (falls verfügbar)
- [ ] capa
- [ ] yara

### Native static
- [ ] JDK + **Ghidra** (GUI + `analyzeHeadless`)
- [ ] **radare2 oder rizin** + `rabin2`
- [ ] **Cutter**
- [ ] `objdump`, `readelf`, `nm` (binutils/llvm)
- [ ] Optional: Binary Ninja free/cloud, IDA-ähnliche Umgebung *nur wenn lizenziert*

### PE/.NET
- [ ] PE-bear oder vergleichbares
- [ ] pestudio-/CFF-Explorer-Konzepte/Tools falls auf Lab-Windows
- [ ] **ILSpy** und/oder **dnSpy**
- [ ] ildasm / dotnet SDK tools
- [ ] de4dot-Konzept/Tool falls nötig

### Android
- [ ] **jadx**
- [ ] **apktool**
- [ ] androguard (pip)
- [ ] apksigner / platform-tools
- [ ] apkleaks (optional)
- [ ] MobSF nur als Konzept/optional self-host

### Firmware/Hex
- [ ] binwalk
- [ ] xxd/hexdump
- [ ] ImHex (optional)
- [ ] 010-Editor-Konzepte falls vorhanden

### Dynamic Lab (optional, isoliert)
- [ ] VM/QEMU + Snapshots
- [ ] gdb/lldb
- [ ] Frida (Version-Match Device)
- [ ] x64dbg auf Windows-Lab
- [ ] strace/ltrace

### Forensics bridge
- [ ] Autopsy und/oder `tsk_*` tools — nur Extraktion

## Doctor-Lauf
1. Jedes Tool: `command -v` + Versionszeile sammeln
2. Report: Tabelle Tool | Status | Version | Notes
3. Fehlendes priorisieren (Ghidra **und** r2 **und** jadx zuerst)
4. Ergebnis ins Ledger legen

## Weiter so
1. Nach Install: Mini-Smoke (kleine APK in jadx, kleines ELF in r2+Ghidra)
2. Master-Skill `yellow-queen-re` starten

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Nur Ghidra installieren und Rest ignorieren
- Frida auf Produktivgerät
