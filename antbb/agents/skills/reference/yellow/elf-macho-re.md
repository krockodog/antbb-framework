---
id: elf-macho-re
queen: yellow
title: "elf-macho-re"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# ELF / Mach-O RE


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Tools
| Zweck | Primär | Alternativen |
|---|---|---|
| Meta | `readelf -a`, `nm -D`, `otool -l` (Mach-O) | `rabin2`, `file`, DIE |
| Disasm | `objdump -d`, r2 | Ghidra, llvm-objdump |
| Deep | Ghidra, Cutter/r2 | Binary Ninja free/cloud |
| Dynamic | gdb/lldb, strace/ltrace | Frida (Lab) |

## Schritte
1. Hash + file + arch (x86_64/arm64/…)
2. Symbols/Imports/RPath/Entitlements (Mach-O)
3. Strip-Status; wenn stripped → capa/floss + r2 `aaa`
4. Deep decompile (Ghidra und/oder r2)
5. Optional Lab-Dynamic
6. Dossier

## Weiter so
1. Shared libs separat hashen und analysieren
2. Reconstruction-loop für Kernfunktionen

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Fat Mach-O: falsche Slice
- PIE/ASLR: Adressen vs. File-Offsets klar trennen
