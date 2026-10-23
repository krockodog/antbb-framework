---
id: apk-android-re
queen: yellow
title: "apk-android-re"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# APK / Android RE


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Wann
- APK/XAPK/AAB-exportierte APKs (autorisiert)

## Tools
| Schicht | Primär | Alternativen |
|---|---|---|
| Java/Kotlin Decompile | jadx (GUI/CLI) | bytecode-viewer, procyon |
| Resources/Smali | apktool | androguard |
| Automation/API graph | androguard | apkleaks, MobSF-Konzepte |
| Secrets | apkleaks, jadx string search | `strings`, manual |
| Signing | apksigner, keytool -printcert | jarsigner -verify |
| Native | extract `.so` → `native-lib-from-apk` → Ghidra **oder** r2 |

## Schritte
1. Hash + `file`; unzip listing
2. `jadx -d out_jadx sample.apk`
3. `apktool d sample.apk -o out_apktool`
4. Manifest: Permissions, exported Components, deep links
5. androguard/apkleaks für Secrets/URLs
6. Smali nur wo jadx scheitert
7. `lib/**/lib*.so` → `native-lib-from-apk`
8. Optional Dynamic: `frida-lab-re` (Oversight, Emulator/Lab)
9. Dossier

## Evidence
- Manifest-Extrakt, interessante Klassenpfade, redacted secrets list, .so hashes

## Weiter so
1. Native Logik → Ghidra/r2
2. Netz/API → dokumentieren (kein Angriff ohne Scope)
3. Ledger

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Packer/DexGuard: zuerst Erkennung, keine falschen „fertigen“ Decompiles
- Signing-Infos ≠ private keys speichern
