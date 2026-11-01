---
id: pb-av-scan
soldier: blue-av
title: ClamAV-Scan erlaubter Pfade
mode: defensive
oversight_required: false
colony: blue
---

# Playbook: ClamAV-Scan

**Soldat:** `blue-av` · **Mode:** defensive · **Oversight:** nein (read-only)

## Ziel
Echte Dateien in-scope mit `clamscan` oder `clamdscan` prüfen. Jeder Befund
nennt Pfad und SHA-256. Ohne Binary: `unavailable`, niemals clean.

## Schritte
1. Pfade aus dem Auftrag nehmen (kein Ganzplatten-Scan)
2. Jeden Pfad gegen den Scope prüfen (default-deny)
3. `clamscan` bevorzugen, sonst `clamdscan`
4. Ausgabe parsen: nur `FOUND` ist eine Infektion
5. SHA-256 der gelesenen Datei an den Befund hängen
6. Fehlt das Binary: Status unavailable, Dateien `not_scanned`

## Checkliste
- [ ] Pfade gegen Scope prüfen
- [ ] Engine ehrlich erkennen
- [ ] SHA-256 je Datei
- [ ] Keine erfundenen Signaturen
- [ ] unavailable ist nicht clean

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Out-of-scope Dateien werden nicht geöffnet
- § 202a-c StGB / CFAA: nur autorisierte Pfade

## Ergebnis
Summary plus je Infektion ein Finding mit Pfad, Hash und Signatur.
