---
id: dotnet-re
queen: yellow
title: "dotnet-re"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# .NET RE


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Tools
| Zweck | Primär | Alternativen |
|---|---|---|
| GUI Decompile | dnSpy, ILSpy | dotPeek |
| CLI | ildasm, ilspycmd | |
| Obfuscation | de4dot-Konzepte | manuelle Cleanup |
| Native mixed-mode | PE tools + Ghidra/r2 für native Teile | |

## Schritte
1. DIE/`file` bestätigt CLR
2. ILSpy/dnSpy: Modules, Types, Resources
3. Entry points, config, embedded resources
4. Obfuscated? → Cleanup-Konzept dokumentieren (de4dot), erneut decompilieren
5. Interessante Methoden → C#-Rekonstruktion in `recovered/`
6. Mixed-mode: native sections → `pe-exe-re` / Ghidra/r2
7. Playbook `playbook-hexgrab-dotnet` wenn Tooling/Hex-Utility
8. Dossier

## Weiter so
1. Unit-Tests gegen rekonstruiertes Verhalten
2. Ledger

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Control-flow obfuscation als „fertig gelesen“ markieren
