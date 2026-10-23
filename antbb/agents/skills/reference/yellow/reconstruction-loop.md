---
id: reconstruction-loop
queen: yellow
title: "reconstruction-loop"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Reconstruction Loop (REA-Stil)

Funktion für Funktion rekonstruieren — inspizieren → Source → bauen/vergleichen → Ledger.


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Wann
- Abandoned-Game / eigener Rebuild
- DX-Ball-/Snowball-/Scrantic-ähnliche Arbeit
- Lesbarer Source wichtiger als „nur verstehen“

## Tools
- Static: Ghidra **und/oder** r2/Cutter
- Build: zielsprachige Toolchain (C/C++/Rust/C#/Kotlin)
- Compare: `radiff2`, checksums, behavior tests, optional byte-match an bekannten Regionen

## Schritte (eine Iteration)
1. **Pick**: eine kleine, gut abgegrenzte Funktion (Helper vor Engine)
2. **Inspect**: Disasm + Decompile; Caller/Callee; Strings/Consts
3. **Recover**: lesbaren Source schreiben (`recovered/<module>/…`)
   - Unsicheres mit `// APPROX:` markieren
4. **Compile** in Isolierung
5. **Compare**:
   - Verhaltenstest (Input→Output)
   - Optional Byte/Size-Match nur wo Methodik es hergibt (DX-Ball-Stil)
6. **Ledger**: Status `done|approx|blocked` + nächste Funktion
7. Dossier-Update

## Evidence
- Vorher/Nachher Notizen, Test-Outputs, Diff-Logs

## Weiter so
1. Nächste Funktion gleicher Schicht
2. Wenn blockiert → `strings-crypto-hunt` oder `dynamic-lab-re`
3. Playbook wählen wenn Domain klar (dxball/th04/…)

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Zu große Funktionen zuerst
- „Sieht ähnlich aus“ ohne Test als Match verkaufen
