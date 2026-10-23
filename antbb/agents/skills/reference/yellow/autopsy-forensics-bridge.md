---
id: autopsy-forensics-bridge
queen: yellow
title: "autopsy-forensics-bridge"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Autopsy / Forensics Bridge (nicht Kern-RE)

**Klarstellung:** Autopsy + The Sleuth Kit = digitale Forensik / Datenrettung / Disk-Artefakte.
Das ist ein **Nachbar** von Reverse Engineering, kein RE-Ersatz.


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Wann
- Disk/VM-Image, unallocated space, File Carve
- Binary/APK/EXE liegt erst nach Extraktion vor

## Schritte
1. Image in Autopsy/TSK (read-only)
2. Relevante Files carven/exportieren
3. Chain-of-custody Notiz: Image-Hash, Export-Hash, Pfad
4. **Handoff** an Format-Skill (`pe-exe-re`, `apk-android-re`, …)
5. Autopsy-Befunde kurz im Dossier verlinken — Analyse passiert in RE-Skills

## Weiter so
1. Sofort RE-Pipeline auf exportierte Samples
2. Nicht in Autopsy „decompilieren“ wollen

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Autopsy mit Ghidra verwechseln
- Ohne Hash-Kette exportieren
