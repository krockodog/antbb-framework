---
id: playbook-snowball-war
queen: yellow
title: "playbook-snowball-war"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Playbook: Snowball-War-Stil (DOS Minigame → modernes Rebuild)


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Schritte
1. `dos-mz-16bit-re` Baseline
2. Scope bewusst klein halten (ein Minigame/Mode)
3. Input, Timing, Collision, Render als getrennte Module rekonstruieren
4. Zielsprache z.B. Rust/SDL2 nur als *Rebuild*, nicht als Byte-identischer Clone-Zwang
5. Verhaltensparität-Checkliste (Tasten, Scores, Grenzen)
6. Dossier + Ledger

## Weiter so
1. Assets extrahieren/dokumentieren
2. Nächsten Mode erst nach Parität

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.
