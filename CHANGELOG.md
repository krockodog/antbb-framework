# Changelog

Alle wesentlichen Änderungen an diesem Projekt werden hier dokumentiert.

## [1.1] – 2026-11-20

### Governance-Startseite
- Neue Governance- und Statusleiste auf der Startseite: Scope-Status, Oversight-Status
  und der globale Kill Switch sind jetzt direkt sichtbar.
- Security Contract und die Kernaussage der Plattform ("Finden und Nachweisen, nicht
  zerstören") sind prominent eingebunden.
- Scope ist als eigenständiges Objekt mit Freigabe-Workflow abgebildet; neue Scope-Felder
  können angelegt und autorisiert werden.
- Risikoklassen SAFE … CRITICAL werden durchgängig ausgewiesen; CRITICAL-Aktionen sind
  gesperrt.
- Audit-/ISMS-Vorschau direkt aus echten Daten – keine Platzhalter, keine Fake-Einträge.
- Öffentliche Startseite maskiert für Nicht-Admins weiterhin alle echten Zieldaten.

### Kill Switch "STOP ALL AGENTS"
- Echter globaler Not-Aus, der alle Agenten anhält, plus Reset.

### Rolle member_plus (Cybersecurity-Kollegen)
- member_plus darf Scopes anlegen, bearbeiten und autorisieren/setzen.
- member_plus darf den globalen Kill Switch auslösen und zurücksetzen.
- Nur die Benutzer- und Rollenverwaltung bleibt Admin-exklusiv.
- Die einfache Rolle member bleibt wie bisher eingeschränkt.
- Oversight-Pflicht für offensive Aktionen und Scope-default-deny gelten unverändert für alle.

### "Alle anwählen" auf allen Königinnen
- Der Ein-Klick-Schalter zum Setzen/Löschen aller Playbooks und Aufgaben einer
  Soldatenkarte gibt es jetzt überall: Red, Blue, Yellow und die kleineren Agenten.
- Einheitliche Tri-State-Logik, Live-Zählwerke und persistente Auswahl über Reload hinweg,
  umgesetzt über eine gemeinsame, wiederverwendbare Komponente.
- Die Auswahl umgeht keine Gates – offensive Starts brauchen weiterhin Oversight.

### Passive OSINT-Werkzeuge
- Die passiven OSINT-Tools sind jetzt fest im Container installiert und verdrahtet, u. a.
  subfinder, amass, theHarvester, waybackurls, gau, assetfinder, findomain, sublist3r,
  waybackpack, phoneinfoga sowie weitere aus dem Extras-Katalog.

### Sonstiges
- Versionsnummern an statischen Skripten/CSS gegen Browser-Cache.
- Cache-schonende, mehrstufige Docker-Builds für die zusätzlichen Werkzeuge.

Screenshots der neuen Oberfläche: siehe `docs/screenshots-v1.1/`.
