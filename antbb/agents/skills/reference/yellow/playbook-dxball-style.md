---
id: playbook-dxball-style
queen: yellow
title: "playbook-dxball-style"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Playbook: DX-Ball-Stil (Function-level C + Byte-Match)

Muster inspiriert von öffentlichen Reconstruction-Reports — Methoden zitieren, keinen proprietären Code kopieren.


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Schritte
1. Inventar der Funktionen (Ghidra/r2)
2. Bottom-up: utils → physics → game state → render
3. Pro Funktion: `reconstruction-loop` mit Verhaltenstest
4. Optional: Byte-Match nur für abgeschlossene, stabile Funktionen; Abweichungen als APPROX
5. Ledger mit Match-% / Test-Status
6. Dossier

## Tools
Ghidra, r2/radiff2, Ziel-C-Toolchain, kleine Test-Harnesses

## Weiter so
1. Nächste ungematchte Funktion
2. Integrationstest Level/Scene

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.
