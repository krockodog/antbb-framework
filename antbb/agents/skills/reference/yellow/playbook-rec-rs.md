---
id: playbook-rec-rs
queen: yellow
title: "playbook-rec-rs"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Playbook: rec-rs / Screen-Recorder RE


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Schritte
1. Imports: Capture-APIs (Desktop Duplication, AVFoundation, PipeWire-Konzepte …)
2. Pipeline: Capture → Convert → Encode → Mux → Write
3. Hotkeys/Config blobs
4. Rekonstruktionsnotiz in modernem Stack (z.B. Rust) als Clean-Room-Skizze
5. Dossier

## Tools
PE/ELF tools, Ghidra/r2, strings/floss, optional Frida auf Lab-Capture-Calls

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.
