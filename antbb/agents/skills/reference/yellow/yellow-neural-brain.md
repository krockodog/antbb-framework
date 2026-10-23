---
id: yellow-neural-brain
queen: yellow
title: "yellow-neural-brain"
brand: All and One - RED-BLUE-Yellow-Ant-Team
builtin: true
source: yellow-queen-skills
---
# Yellow Neural Brain

Eigenes Neural Brain für Yellow Queen — **getrennt** von antbb `/brain` (Red) und Blue Queen.

## Harte Gates (immer)
- Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research, Malware-Lab.
- Kein Crack/DRM/Lizenz-Bypass, kein Diebstahl von Software.
- Secrets/Keys nie in Reports oder Repos speichern (redact).
- Dynamic/Execution nur in Lab-VM und mit Oversight-Bestätigung.

## Wann nutzen
- UI/Produkt: Yellow-Brain-Ansicht bauen oder befüllen
- Nach Orchestration-Hops Status zeigen
- Soldat/Playbook-Detail mit Erklärbär-Text öffnen
- Judith fragt „was macht Yellow gerade?“

## Was das Brain zeigt
1. **Orchestration-Hops** — classify → toolchain → skill/soldat → merge (Run-Card)
2. **Live-Status** — Phase, aktiver Soldat, Blocker, Oversight-Flags
3. **Soldat-/Playbook-Detail** — Checkliste + **Erklärbär** (warum/was/next)
4. **Evidence-Chips** — Links zu `evidence/`, Dossier, Ledger
5. **Next-3** — aus Ledger, klar priorisiert

## Datenfluss
```
yellow-queen-orchestrate (Run-Card)
        │
        ├─ soldiers/skills → evidence snippets
        │
        ├─ re-result-dossier ──► Brain: Kurzfazit + Erklärung + Evidenz-Tabelle
        └─ re-progress-ledger ─► Brain: Phase, Completed, Next-3, Blocker
```

## Felder (Minimal-Schema)
```markdown
## Brain Snapshot
- sample_sha / title
- phase: triage|static|reconstruct|dynamic|merge|idle
- active_soldier / active_playbook
- hops: [ {op, skill, summary_de} ]
- erklaerbaer: { warum, fund, next }
- dossier_path / ledger_path
- updated_at: Europe/Berlin
```

## Regeln
- Brain ist **Anzeige + Navigation**, nicht stilles Log
- Jeder Hop braucht einen deutschen `summary_de` (Erklärbär)
- Keine Secrets im Brain
- Nicht mit Red `/brain` mischen

## Weiter so
1. Nach jedem Skill-Ende Snapshot schreiben/aktualisieren
2. UI liest Ledger+Dossier; fehlt Erklärung → Orchestrator nachziehen
3. Eye-Catcher: lesbare Hops statt Roh-Dump

## Erklärbär (Pflicht — Deutsch, klar)

Yellow Queen = Orchestratorin **und** Erklärerin. Nach jedem Schritt in Alltagssprache:

1. **Warum dieses Tool?** (1–2 Sätze; Alternativen kurz nennen)
2. **Was bedeutet der Fund?** (ohne Jargon-Wall; Adresse/Offset behalten)
3. **Was tun wir als Nächstes?** (konkret, nummeriert)

Keine reinen Dump-Outputs ohne Erklärung. Fachbegriffe beim ersten Mal kurz übersetzen.
