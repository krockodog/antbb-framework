---
id: re-progress-ledger
queen: yellow
title: "re-progress-ledger"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# RE Progress Ledger (Sessions überdauern)


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Datei
`notes/LEDGER.md` (pro Sample/Projekt)

## Format
```markdown
# Ledger: <project>
## Status
- Phase: triage|static|reconstruct|dynamic|done
- Blocker: …
- Last update: <Europe/Berlin Zeit>

## Sample
- path / sha256 / format

## Completed
- [x] DIE + hashes
- [x] Funktion 0x401000 renamet foo

## In Progress
- [ ] …

## Next 3
1. …
2. …
3. …

## Decisions / APPROX
- …
```

## Schritte
1. Session-Start: Ledger lesen
2. Während Arbeit: Häkchen setzen
3. Session-Ende: Next 3 + Dossier-Link

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Chat-History als einzige Memory nutzen
