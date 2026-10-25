"""Lesbare Task-Beschreibungen für Blue-Playbooks ohne eigene `tasks`.

Wird von registry._tasks_for per setdefault nachgeladen – überschreibt nie
vorhandene TASK_CATALOG-Einträge oder `Playbook.tasks`.
"""
from __future__ import annotations

BLUE_TASK_EXTRA: dict[str, list[str]] = {
    "backup-coverage": [
        "Backup-Werkzeug erkennen (restic/borg/rsnapshot/duplicity/rclone)",
        "systemd-Timer und cron-Jobs auf Backup-Zeitplan prüfen",
        "Lücke melden, wenn kein automatischer Zeitplan existiert",
        "nur lesen – keine Backups anlegen oder löschen"],
    "backup-integrity-check": [
        "Alter des neuesten Archivs gegen die Frische-Schwelle prüfen",
        "gzip/tar/zip-Archive per Test-Lesezugriff auf Lesbarkeit prüfen",
        "Ergebnis ins Posture-Ledger übernehmen (BESTÄTIGT bei Beleg)",
        "kein Restore – nur read-only Verifikation"],
    "fw-ruleset-audit": [
        "Paketfilter erkennen (ufw / nftables / iptables)",
        "Policy und aktive Regeln lesen (soweit Rechte reichen)",
        "Default-Deny-Lücken und offene Listener korrelieren",
        "fehlende Rechte ehrlich als 'info' melden – nie raten"],
    "identity-account-audit": [
        "Konten mit UID 0 außer root zählen (nur Zahlen, keine Namen)",
        "leere Passwort-Hashes in /etc/shadow zählen (nur Anzahl, keine Hashes)",
        "Passwort-Alterung und Mindestlänge in login.defs prüfen",
        "Mitglieder privilegierter Gruppen (sudo/wheel/admin) zählen"],
    "identity-ssh-key-hygiene": [
        "Modus von ~/.ssh und authorized_keys prüfen (700/600)",
        "private Schlüssel auf zu offene Rechte prüfen",
        "Login-Drosselung (faillock/fail2ban/sshd MaxAuthTries) bewerten",
        "Fix-Befehle nur als Vorschlag (chmod) ausgeben"],
    "identity-lockdown-apply": [
        "Oversight-Freigabe prüfen (default-deny)",
        "Konto-Sperre bzw. Rechte-Korrektur als Befehl vorschlagen",
        "nur mit Freigabe anwenden und im Ledger dokumentieren",
        "Rollback-Hinweis mitliefern"],
    "log-pipeline-audit": [
        "journald-Konfiguration prüfen (Persistenz, Storage=persistent)",
        "auditd-Prozess und Regelsatz nachweisen",
        "Log-Weiterleitung (rsyslog/SIEM) auf Existenz prüfen",
        "Lücken als blue-logintegrity-gap ins Ledger"],
    "log-tamper-resistance": [
        "Dateirechte in /var/log auf Manipulierbarkeit prüfen",
        "logrotate-Konfiguration und Aufbewahrung bewerten",
        "Zeitsynchronisation (chrony/ntp/timesyncd) bestätigen",
        "Aktivitätslücken im Logfluss erkennen (Zeitlöcher)"],
}

TOOL_LABELS: dict[str, str] = {
    "passwd-uid0": "UID-0-Konten zählen",
    "shadow-empty-hash": "leere Passwort-Hashes zählen",
    "login-defs": "login.defs (Passwort-Policy) lesen",
    "admin-groups": "privilegierte Gruppen prüfen",
    "ssh-dir-modes": "SSH-Verzeichnisrechte prüfen",
    "private-key-modes": "Rechte privater Schlüssel prüfen",
    "faillock-check": "Login-Drosselung prüfen",
    "lock-account-gated": "Konto sperren (nur mit Oversight)",
    "journald-conf": "journald-Persistenz prüfen",
    "auditd-process": "auditd-Prozess prüfen",
    "rsyslog-forwarding": "Log-Weiterleitung prüfen",
    "var-log-modes": "Rechte in /var/log prüfen",
    "logrotate": "Rotation/Aufbewahrung prüfen",
    "ntp-sync": "Zeitsynchronisation prüfen",
    "activity-gap": "Aktivitätslücken im Log suchen",
    "tool-detect": "Backup-Werkzeug erkennen",
    "systemd-timers": "systemd-Timer prüfen",
    "cron-scan": "cron-Zeitpläne prüfen",
    "freshness-age": "Archiv-Alter prüfen",
    "gzip-tar-zip-test": "Archiv-Lesbarkeit testen",
    "run-watch": "Wächter-Lauf starten",
}
