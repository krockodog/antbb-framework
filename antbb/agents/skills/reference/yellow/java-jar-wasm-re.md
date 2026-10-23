---
id: java-jar-wasm-re
queen: yellow
title: "java-jar-wasm-re"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Java JAR / WASM RE


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Tools
| Ziel | Primär | Alternativen |
|---|---|---|
| JAR | jadx, CFR, procyon | javap, bytecode-viewer |
| WASM | wasm2wat, wabt, Ghidra WASM | wasm-decompile, chromedevtools-Konzepte |

## Schritte
1. Hash; jar tf / wasm-objdump
2. Decompile; Entry/Exports
3. Native JNI/WASM imports → native pipeline
4. Dossier

## Weiter so
1. Obfuscation erkennen und eingrenzen
2. Reconstruction kleiner Module

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.
