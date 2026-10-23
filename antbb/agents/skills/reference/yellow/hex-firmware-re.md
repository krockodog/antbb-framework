---
id: hex-firmware-re
queen: yellow
title: "hex-firmware-re"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Hex / Firmware RE


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Tools
| Zweck | Primär | Alternativen |
|---|---|---|
| Carve/Scan | binwalk | firmware-mod-kit-Konzepte |
| Hex view | ImHex, xxd/hexdump | 010 Editor-Konzepte |
| Load/Disasm | Ghidra (Processor + Base) | r2 (`r2 -a arm -b 16/32`), objdump |
| FS extract | binwalk -e, unsquashfs, … | manuell |

## Schritte
1. Hash; Entropy-Plot (binwalk -E)
2. Signatures (`binwalk`); extrahieren
3. Architektur-Hypothese (ARM/MIPS/…); Reset-Vektor/Strings
4. In Ghidra/r2 mit Base Address laden (Hypothesen dokumentieren)
5. Interrupt-Tabellen / Boot-Pfade zuerst
6. Dossier inkl. Base-Address-Konfidenz

## Weiter so
1. Gefundene Dateisysteme → separat analysieren
2. Crypto-Konstanten → `strings-crypto-hunt`

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Falsche Base → komplette Analyse wertlos; immer Konfidenz angeben
