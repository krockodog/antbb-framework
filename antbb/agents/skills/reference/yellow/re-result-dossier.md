---
id: re-result-dossier
queen: yellow
title: "re-result-dossier"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# RE Result Dossier (Pflicht-Template)

Jeder RE-Lauf endet hiermit — sonst ist die Arbeit nicht „fertig“.


## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.


## Wann
- Nach jedem Skill/Playbook-Schritt
- Vor Session-Ende
- Vor Übergabe an Judith

## Template (kopieren)

```markdown
# Dossier: <kurzname> — <YYYY-MM-DD HH:MM Europe/Berlin>

## Meta
- Sample: <path>
- SHA256: <hash>
- Format/Arch: <PE x64 | APK arm64 | …>
- Autorisierung: <kurz>
- Tools genutzt: <Liste Primär + Alternativ>
- Ledger: <path>

## Erklärung
- Warum dieser Weg/dieses Tool: …
- Was die wichtigsten Funde bedeuten: …
- Was als Nächstes passiert (und warum): …

## Kurzfazit
<1–3 Sätze, was jetzt sicher ist>

## Evidenz-Tabelle
| Fund | Offset/Adresse | Tool | Bedeutung | Konfidenz (hoch/mittel/niedrig) |
|---|---|---|---|---|
| … | 0x… | ghidra/r2/jadx/… | … | … |

## Fakten
- …

## Hypothesen (unbestätigt)
- …

## Bewusste Approximationen / Offen
- …

## Artefakte
- evidence/…
- recovered/…
- notes/…

## Weiter so (nächste 3 Schritte)
1. …
2. …
3. …
```

## Erklärung (Erklärbär-Block im Dossier)

Im Template **immer** diesen Abschnitt füllen (Alltagsdeutsch):

```markdown
## Erklärung
- Warum dieser Weg/dieses Tool: …
- Was die wichtigsten Funde bedeuten: …
- Was als Nächstes passiert (und warum): …
```

Regel: Wenn Judith nur diesen Abschnitt liest, muss der Lauf verständlich sein.

## Qualitäts-Gates
- Mindestens ein Tool-Name pro Evidenzzeile
- Keine Secrets im Klartext
- Nächste Schritte ausführbar (Befehl/Skill/Adresse)

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.

## Pitfalls
- Nur Narrativ ohne Adressen
- Hypothesen als Fakten verkaufen
