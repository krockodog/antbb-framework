---
id: playbook-th04-math
queen: yellow
title: "playbook-th04-math"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Playbook: TH04-Math (16-bit numerische Helper)


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Schritte
1. Konstanten/Tabellen suchen (`strings-crypto-hunt`, Hex-View)
2. Kleine Pure Functions (sin/atan Approx, angle, speed) in Ghidra/r2 isolieren
3. Gegen Testvektoren in High-Level nachbauen
4. Fixed-point vs float klar dokumentieren
5. Dossier

## Weiter so
1. Helper in Engine-Loop einhängen
2. Visual/Gameplay-Validierung im Lab

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.
