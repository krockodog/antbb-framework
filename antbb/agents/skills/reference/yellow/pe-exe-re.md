---
id: pe-exe-re
queen: yellow
title: "pe-exe-re"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# PE / EXE / DLL RE


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Wann
- Windows PE32/PE32+ EXE/DLL/SYS (autorisiert)

## Tools
| Zweck | Primär | Alternativen |
|---|---|---|
| Packer/Compiler | Detect It Easy (DIE) | `rabin2 -I`, ExeinfoPE-Konzepte |
| PE Struktur | PE-bear, pestudio-Konzepte, CFF Explorer-Konzepte | `objdump -x`, `rabin2` |
| Capabilities | capa | yara, Import-Listen |
| Strings | floss / strings | r2 `izz` |
| Native deep | Ghidra, r2/Cutter | IDA-ähnliche Workflows, Binary Ninja free/cloud |
| .NET branch | → `dotnet-re` (dnSpy/ILSpy/…) | |
| Dynamic | x64dbg-Konzepte, Frida, Procmon-Konzepte | nur Lab |

## Schritte
1. Hash, DIE, `file`
2. Wenn Packer → `packer-unpack-re` bevor tiefe Analyse
3. Wenn CLR/.NET Header → `dotnet-re`
4. Imports/Exports/Resources/Sections dokumentieren
5. capa + floss
6. Deep static: Ghidra **und/oder** r2
7. Bei Malware-Verdacht: `malware-triage-re`
8. Dossier

## Evidence
- DIE verdict, section table, import shortlist, capa matches

## Weiter so
1. Entry/WinMain → reconstruction oder malware path
2. Resources (Icons/Dialogs/Config blobs) → `strings-crypto-hunt`

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Packed Image in Ghidra laden und glauben, der Code sei final
