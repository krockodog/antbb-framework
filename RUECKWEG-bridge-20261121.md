# RUECKWEG — Red→Blue→Re-Check-Brücke + Brain-Entsilung + Parsing/LLM-Telemetrie

Datum: 2026-11-21 (Europe/Berlin)
Arbeitsbaum: /workspace/antbb-gov (Commit 53bc21e + lokale Mods)
KEIN git commit / KEIN push / KEIN Deploy ohne Marks Go.

## Backup
Ordner: /workspace/antbb-backup-bridge-20261121-180901
- antbb-orig/   : Dateikopien VOR der Änderung
- data/antbb.db, data/yellow.db : lokale DB-Snapshots
- before_counts.txt : Tabellen-Zählungen vorher

## Neu angelegte Dateien (entfernen zum Zurücksetzen)
- antbb/parseutil.py
- antbb/bridge.py
- antbb/yellow_bridge.py
- antbb/llm_telemetry.py
- tests/test_bridge_correlation.py (falls vorhanden)
- RUECKWEG-bridge-20261121.md (diese Datei)

## Geänderte Dateien (aus Backup zurückkopieren)
- antbb/store.py
- antbb/queen.py
- antbb/blue_queen.py
- antbb/service.py
- antbb/web/app.py
- antbb/brain_ops.py
- antbb/tools/kali.py
- antbb/greenbone.py
- antbb/agents/analysis.py
- antbb/remediation.py
- antbb/web/templates/history.html
- antbb/jobs.py

## Vollständiges Zurücksetzen (lokal, kein Deploy)
```bash
B=/workspace/antbb-backup-bridge-20261121-180901
cd /workspace/antbb-gov
rm -f antbb/parseutil.py antbb/bridge.py antbb/yellow_bridge.py antbb/llm_telemetry.py
for f in store.py queen.py blue_queen.py service.py brain_ops.py greenbone.py \
         remediation.py jobs.py tools/kali.py agents/analysis.py \
         web/app.py web/templates/history.html; do
  cp -a "$B/antbb-orig/antbb/$f" "antbb/$f"
done
# DB: additive Spalten bleiben harmlos; optional Snapshot zurück:
# cp -a "$B/data/antbb.db" data/antbb.db
```

## Gates (unverändert)
Scope default-deny, Oversight für Offensive/Apply, mode_policy auto,
CRITICAL gesperrt, Kill-Switch nur Admin+member_plus,
Benutzer-/Rollenverwaltung Admin-exklusiv, nicht destruktiv, reversibel.
