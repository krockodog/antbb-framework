---
id: dynamic-lab-re
queen: yellow
title: "dynamic-lab-re"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Dynamic Lab RE (VM-only)


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


**Oversight-Gate:** Vor Start Judith/Operator kurz bestätigen lassen.

## Tools
| Plattform | Primär | Alternativen |
|---|---|---|
| Linux | gdb, strace, ltrace | rr, perf-Konzepte |
| Windows | x64dbg-Konzepte, Procmon/Process-Hacker-Konzepte | WinDbg-Konzepte |
| Cross | QEMU/VM Snapshots | Frida → `frida-lab-re` |

## Schritte
1. Snapshot vor Run
2. Netz idealerweise isoliert/fake
3. Hypothese formulieren (welche Funktion/Verhalten)
4. Minimaler Run; Logs sammeln
5. Breakpoints an zuvor statisch gefundenen Adressen
6. Findings zurück in Static (Rename/Comments)
7. Snapshot revert; Dossier

## Weiter so
1. Frida für API-Hooks wenn sinnvoll
2. Reconstruction mit neuen Fakten

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Kein Snapshot
- Produktiv-Host
