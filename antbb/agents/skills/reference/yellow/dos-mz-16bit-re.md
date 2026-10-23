---
id: dos-mz-16bit-re
queen: yellow
title: "dos-mz-16bit-re"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# DOS MZ / 16-bit RE


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Tools
| Zweck | Primär | Alternativen |
|---|---|---|
| Unpack hints | DIE, bekannte EXEPACK-Muster | manuelle Stub-Analyse |
| Disasm | Ghidra (x86 real-mode) | r2 (`asm.bits=16`), DOSBox+Debugger-Konzepte |
| Runtime | DOSBox / DOSBox-X Lab | QEMU |

## Schritte
1. MZ Header, Overlay, Packer?
2. Unpack nur dokumentiert/sicher → `packer-unpack-re`
3. Segment:Offset-Denken; Interrupt-Nutzung (21h, 10h, …)
4. Kleine Helper (Math, RNG, Blit) vor Game-Loop
5. Playbooks: `playbook-snowball-war`, `playbook-th04-math`
6. Dossier

## Weiter so
1. Bounded Minigame reconstruction
2. Asset-Formate (Sprites/PCM) separat dokumentieren

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- 32-bit Annahmen auf 16-bit Code
