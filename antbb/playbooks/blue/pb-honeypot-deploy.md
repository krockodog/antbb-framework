---
id: pb-honeypot-deploy
soldier: blue-honeypot
title: Loopback-Canary starten
mode: defensive
oversight_required: true
colony: blue
---

# Playbook: Canary-Deploy

**Soldat:** `blue-honeypot` · **Mode:** defensive · **Oversight:** JA (default-deny)

## Ziel
Einen low-interaction Köder wirklich starten, nur auf dem Loopback, nur mit
Oversight und Scope.

## Was wirklich passiert
1. Ohne Oversight oder ohne Scope `decoy`/`localhost`: denied, kein Socket.
2. HTTP-Canary auf `127.0.0.1` (Default-Port 8089, im Test Port 0): antwortet
   mit dem Text `canary`, protokolliert die Request-Zeile (gekürzt).
3. SSH-Canary daneben: sendet nur `SSH-2.0-antbb-canary` und schließt. Kein
   Login, keine Shell.
4. Cowrie wird nicht installiert und nicht gestartet.
5. Bind an `0.0.0.0` oder ein fremdes Interface wird abgelehnt.
6. `stop_canary` beendet die Listener wieder.

## Checkliste
- [ ] Oversight bestätigt
- [ ] Scope bestätigt
- [ ] Nur 127.0.0.1
- [ ] Versuche lokal geloggt
- [ ] Bind-Fehler ehrlich gemeldet

## Safety
- Keine echten Credentials, kein Relay
- § 202a-c StGB / CFAA gilt für den aktiven Start
- Log-Zeilen sind gekürzt, keine Secrets aus dem Framework

## Ergebnis
Finding mit Ports, Status `applied`/`partial`/`failed`/`denied`. Kein
stilles „gestartet“, wenn der Socket nicht annimmt.
