---
id: strings-crypto-hunt
queen: yellow
title: "strings-crypto-hunt"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Strings / Crypto / Config Hunt


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Tools
`strings` · floss · r2 `izz` · ImHex · binwalk · yara · bekannte Crypto-Konstanten (AES S-Box etc.) · capa

## Schritte
1. ASCII/UTF-16 dumps; FLOSS für encoded
2. URL/Pfad/Registry/Fehlertexte klassifizieren
3. Crypto-Konstanten & Blob-Kandidaten markieren
4. Xrefs in Ghidra/r2 zu Nutzung
5. Config-Parser-Hypothesen → reconstruction-loop
6. Dossier (Secrets redacted!)

## Weiter so
1. Parser-Funktion rekonstruieren
2. Yara-Rule für Lab-Sammlung (optional)

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.
