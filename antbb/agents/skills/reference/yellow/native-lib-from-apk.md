---
id: native-lib-from-apk
queen: yellow
title: "native-lib-from-apk"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Native Lib from APK


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Schritte
1. `unzip -l app.apk | rg 'lib/.*\.so$'`
2. Extract je ABI (`lib/arm64-v8a/…`); SHA256
3. DIE/file; Symbols?
4. Ghidra **und/oder** r2/Cutter (ARM/AArch64)
5. JNI_OnLoad / Java_*-Exports zuerst
6. Zurück zu jadx: native Methoden mappen
7. Dossier

## Tools
apktool/unzip · jadx (für JNI-Namen) · Ghidra · r2 · readelf/nm

## Weiter so
1. Frida-Hooks auf native Exports im Lab
2. reconstruction-loop für kritische native funcs

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.
