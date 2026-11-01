---
id: pb-av-quarantine
soldier: blue-av
title: Quarantäne-Move und Re-Check
mode: defensive
oversight_required: true
colony: blue
---

# Playbook: Quarantäne

**Soldat:** `blue-av` · **Mode:** defensive · **Oversight:** JA (default-deny)

## Ziel
Eine infizierte Datei aus dem erlaubten Pfad nehmen, ohne sie zu löschen, und
danach belegen, ob der Originalpfad damit sauber ist.

## Was wirklich passiert
1. Oversight (`active`) und Scope müssen beide greifen, sonst denied.
2. Reguläre Datei, kein Symlink, kein Systempfad (`/etc`, `/usr`, `/bin`, …).
3. `shutil.move` nach `ANTBB_QUARANTINE_DIR` oder
   `~/.local/share/antbb/quarantine/<id>.bin`.
4. Manifest: Originalpfad, Modus, SHA-256, Rollback über `restore_file`.
5. Re-Check: `GESCHLOSSEN` nur wenn der Originalpfad leer ist und der Hash
   in der Quarantäne stimmt. Bloßes Löschen schließt den Fund nicht.
6. Netz-Isolation (Watcher/Incident) ist separat: `ufw deny from <eine IP>`,
   nur wenn `ufw` installiert ist. Sonst `unavailable`.

## Checkliste
- [ ] Oversight bestätigt
- [ ] Scope bestätigt
- [ ] Move statt Löschen
- [ ] Manifest geschrieben
- [ ] Re-Check mit Vorher/Nachher

## Safety
- Keine Secrets/PII in Logs oder Evidence
- Systempfade werden nicht verschoben
- § 202a-c StGB / CFAA bleibt für aktive Schritte stehen

## Ergebnis
Finding `GESCHLOSSEN` nur mit Beleg. Sonst offen und ehrlich.
