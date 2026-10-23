---
id: ghidra-pipeline
queen: yellow
title: "ghidra-pipeline"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Ghidra Pipeline

Eine starke Static-Pipeline — **nicht** die einzige. Parallele/Alternative: `radare2-cutter-pipeline`, objdump/readelf, capa.


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Wann
- Native Code (PE/ELF/Mach-O/Firmware/.so) decompilieren
- Xrefs, Data-Types, Scripts, Headless-Batch

## Prerequisites
- JDK 17+ · Ghidra installiert · genug RAM · Sample gehashed
- Optional: Ghidra scripts Verzeichnis, Processor modules für Firmware

## Schritte
1. **Import**: GUI oder Headless
   ```
   analyzeHeadless <projDir> <projName> -import <binary> \
     -processor <PROC> -cspec <CSPEC> -analysisTimeoutPerFile 300 \
     -postScript ExportDecomp.java <outDir>
   ```
2. **Auto-Analyze** mit sinnvollen Analyzer; bei Firmware Base-Address setzen
3. **Entry & Imports** kartieren; externe Libraries notieren
4. **Funktion wählen** (klein starten): Rename, Comments, Data Types
5. **Decompile** lesen; mit Disassembly abgleichen
6. **Xrefs** (Callers/Callees) → Callgraph-Notiz
7. **Evidence export**: Decompiled C, Listing Snippet, Function list, String refs
8. Cross-check mit **r2** (`pdf`, `pdg` falls verfügbar) oder `objdump -d` an kritischen Adressen
9. Ergebnis → `reconstruction-loop` / `re-result-dossier`

## Evidence
- `evidence/ghidra/<sha>/functions.md`
- Decompiled Snippets mit Adresse
- Analyzer-Log / Processor / Image base

## Weiter so
1. Schlechte Decompile-Qualität? → `radare2-cutter-pipeline` oder andere Architektur/Compiler-Annahme
2. Eine Funktion rekonstruieren → `reconstruction-loop`
3. Ledger updaten

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Falsche Image Base (besonders Firmware)
- Packed Binary analysieren ohne Unpack → `packer-unpack-re`
- Headless ohne Timeout hängt
