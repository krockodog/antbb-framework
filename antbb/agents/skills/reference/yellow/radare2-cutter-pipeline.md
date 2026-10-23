---
id: radare2-cutter-pipeline
queen: yellow
title: "radare2-cutter-pipeline"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# radare2 / rizin + Cutter Pipeline

Gleichwertige Static-Pipeline neben Ghidra. Oft schneller für Triage, Scripting, Patch-Experimente.


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Wann
- Schnelle CLI-Analyse, Automation
- Ghidra-Decompile unbrauchbar / Abgleich nötig
- Cutter-GUI gewünscht

## Tools
- Primär: `r2` / `rizin`, `rabin2`, `radiff2`, `rahash2`
- GUI: Cutter (rizin-basiert)
- Ergänzend: `capa`, `strings`/`floss`, DIE

## Schritte
1. Triage:
   ```
   file sample
   rahash2 -a sha256 sample
   rabin2 -I -l -i -z sample
   ```
2. Session:
   ```
   r2 -A sample          # oder aaa manuell vorsichtiger
   aaa                   # Analyse (bei großen Binaries abgestuft: aa; aac; ...)
   afl                   # functions
   iz; izz               # strings
   ii; il                # imports/libs
   s main; pdf           # disasm
  pdg                   # decompile wenn r2ghidra/decai verfügbar
   ```
3. In Cutter: Import → Analyze → Functions/Decompiler/Graph
4. Interessante Funktionen benennen; Comments; Flags
5. Diff bei Reconstruction: `radiff2 -AC a.bin b.bin`
6. Evidence export (Textdumps, Graph-Screenshots nur wenn nötig)
7. Cross-check kritische Stellen in Ghidra wenn Typen/Structs komplex

## Evidence
- `evidence/r2/<sha>/afl.txt`, `imports.txt`, `strings.txt`
- Disasm/Decompile-Snippets mit Adresse
- Cutter project path falls genutzt

## Weiter so
1. Tiefe Typen/Structs → Ghidra
2. Dynamic → `frida-lab-re` / `dynamic-lab-re`
3. Dossier + Ledger

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- `aaa` auf riesigen Binaries = lange Laufzeit; abgestuft analysieren
- Decompiler-Plugin fehlt → klar sagen, Disasm nutzen
