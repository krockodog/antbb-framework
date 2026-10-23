---
id: playbook-ui-kit-extract
queen: yellow
title: "playbook-ui-kit-extract"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Playbook: UI-Kit Extract (Desktop Client → UI Structure)


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Tools
- Strings/resources · Electron/React Bundle Analyse falls vorhanden · Native UI: Ghidra/r2 / .NET tools · jadx bei Android-UI

## Schritte
1. Tech-Stack erkennen (Electron/Qt/WPF/Win32/…)
2. Component-/Resource-Tree kartieren
3. Design-Tokens (Farben, Spacing) aus Resources
4. Wiederaufbau als eigenes UI-Kit (keine 1:1 proprietary assets klauen)
5. Dossier

## Weiter so
1. Storybook/Demo-Seiten für rekonstruierte Komponenten

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.
