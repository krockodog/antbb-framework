<p align="center">
  <img src="docs/images/brain-city-capital.png" alt="Neuronales Gehirn: Thron der Roten Königin in der Ameisenstadt" width="720">
</p>

<h1 align="center">All and One - RED-BLUE-Yellow-Ant-Team</h1>

<p align="center">
Bug Bounty und Pentest (Red), Schutz und Hardening (Blue), Reverse Engineering (Yellow). Ein Prozess, ein Port, eine Adresse.
</p>

English: [README.md](README.md)

<p align="center">
  <img alt="Sprache Deutsch" src="https://img.shields.io/badge/lang-DE-111111">
  <img alt="Sprache Englisch" src="https://img.shields.io/badge/lang-EN-111111">
  <img alt="Python 3.11 oder neuer" src="https://img.shields.io/badge/Python-3.11%2B-3776AB">
  <img alt="Linux" src="https://img.shields.io/badge/platform-Linux-000000">
  <img alt="MIT-Lizenz" src="https://img.shields.io/badge/license-MIT-2ea44f">
  <img alt="Sicherheit: Scope default-deny und menschliches Oversight" src="https://img.shields.io/badge/safety-default--deny_%2B_Oversight-1f6feb">
  <img alt="GitHub-Sterne" src="https://img.shields.io/github/stars/krockodog/antbb-framework">
</p>

Orchestrierte Ameisenfarmen — die vom Bug Bounty und Pentest über Reverse Engineering bis zum Schutz und Hardening helfen. Jedes echte Ergebnis – Ziele, Läufe, Befunde, Logs – mehrt den Reichtum der Ameisenstadt, und dieses Wachstum kennt keine Endstufe: Wissen selbst ist ihr Wohlstand. Je mehr Wissen und Macht eine Königin sammelt, desto besser weiß sie ihr Volk zu führen, einzusetzen und zu schützen. Die Ausbaustufe der Stadt wird bereits aus den echten Zählern berechnet und angezeigt (ab 1 Hütten, 10 Brunnen, 50 Steinhäuser, 200 Türme, 1000 moderne Gebäude); die zugehörigen 3D-Gebäude sind in Arbeit.

> Unbefugtes Ausspähen, Abfangen oder Vorbereiten von Angriffen auf Daten ist strafbar (§ 202a–c StGB; im US-Kontext der CFAA). Aktive Arbeit läuft nur mit bestätigtem Human Oversight und einem konkreten Ziel im Scope. Der Hinweis ersetzt kein Oversight.

## Schnellstart

Frischer Klon auf Linux (getestet auf Debian/Ubuntu). Die Unit [`deploy/antbb.service`](deploy/antbb.service) läuft als `User=antbb` / `Group=antbb`, mit `WorkingDirectory=/opt/antbb`, und liest `/opt/antbb/antbb.env`. Die `useradd`-Zeile ist dieselbe wie in [DEPLOY.md](DEPLOY.md). Auf Debian/Ubuntu legt sie die Gruppe `antbb` an; `--create-home` legt `/opt/antbb` an. Weil das Verzeichnis dann schon existiert, klont man daneben und kopiert mit dem `rsync` aus `DEPLOY.md`.

```bash
# Konto antbb, Gruppe antbb, Home /opt/antbb
sudo useradd --system --create-home --home-dir /opt/antbb --shell /usr/sbin/nologin antbb
git clone https://github.com/krockodog/antbb-framework.git
sudo rsync -a --exclude .git --exclude antbb.env --exclude data ./antbb-framework/ /opt/antbb/
# Interpreter, den die Unit ausführt: /opt/antbb/.venv/bin/python
sudo python3 -m venv /opt/antbb/.venv
sudo /opt/antbb/.venv/bin/pip install -r /opt/antbb/requirements.txt
sudo cp /opt/antbb/antbb.env.example /opt/antbb/antbb.env
sudo chmod 600 /opt/antbb/antbb.env
# Fragt das Passwort ab, nimmt es nicht als Argument. Ausgabe ist nur der Hash.
cd /opt/antbb && sudo .venv/bin/python -m antbb.webauth hash-password
```

Die ausgegebene Zeile als root in `/opt/antbb/antbb.env` schreiben: `ANTBB_ADMIN_PASSWORD_HASH=...` (Format `pbkdf2_sha256:<iterations>:<salt_hex>:<hash_hex>`). Fehlt `ANTBB_ADMIN_USER`, heißt der Account `admin`. Danach Besitz abgeben, sonst kann `antbb` die Datei mit Modus 600 nicht lesen:

```bash
sudo chown -R antbb:antbb /opt/antbb
sudo cp /opt/antbb/deploy/antbb.service /etc/systemd/system/antbb.service
sudo systemctl daemon-reload
sudo systemctl enable --now antbb
```

Direktstart, ebenfalls als `antbb`. `python -m api` liest `antbb.env` nicht selbst; systemd lädt die Datei über `EnvironmentFile`. In der Shell muss sie in derselben Sitzung gesourct werden:

```bash
sudo -u antbb bash -c 'cd /opt/antbb && set -a && . ./antbb.env && set +a && exec .venv/bin/python -m api --host 127.0.0.1 --port 1001'
```

Danach im Browser: http://127.0.0.1:1001/login

> Ohne `ANTBB_ADMIN_PASSWORD_HASH` oder `ANTBB_ADMIN_PASSWORD` startet der Prozess nicht. Es gibt kein Default-Passwort.
>
> Nicht als root starten. Die Einstiege verweigern das; die Unit setzt `User=antbb`.
>
> Der Bind bleibt `127.0.0.1`, außer `ANTBB_EXPOSE=1` ist absichtlich gesetzt. Dieses Opt-in schreibt eine Warnung.
>
> Fernzugriff über einen SSH-Tunnel (`ssh -L 1001:127.0.0.1:1001 <user>@<host>`), dann dieselbe URL lokal öffnen. Den Port nicht veröffentlichen.

`./run.sh` ist der andere Starter: er ruft `install-and-start.sh` auf, sourct `antbb.env` selbst und bindet standardmäßig `127.0.0.1:8000`, nicht Port 1001. Auch er verweigert root, einen fehlenden Hash und einen Bind jenseits von Loopback ohne `ANTBB_EXPOSE=1`.

## Inhalt

1. [Schnellstart](#schnellstart)
2. [Überblick](#überblick)
3. [Red Queen – Offensive Sicherheit](#red-queen--offensive-sicherheit)
4. [Blue Queen – Schutz und Hardening](#blue-queen--schutz-und-hardening)
5. [Yellow Queen – Reverse Engineering](#yellow-queen--reverse-engineering)
6. [Gemeinsame Bereiche](#gemeinsame-bereiche)
7. [Architektur](#architektur)
8. [Installation](#installation)
9. [Betrieb](#betrieb)
10. [Leitplanken und Sicherheitsmodell](#leitplanken-und-sicherheitsmodell)
11. [Roadmap](#roadmap)
12. [Credits](#credits)
13. [Lizenz und Hinweis](#lizenz-und-hinweis)

## Überblick

| Team | Rolle | Kern |
|---|---|---|
| **Red Queen** | Red-Teaming | Bug Bounty und Pentest im engen Scope, 5-Phasen-Pipeline, Findings mit Proof-Gate, Fix-Brücke zu Blue, Funk-Labor (WLAN/BT/IoT) mit Späher |
| **Blue Queen** | Blue Safety-Teaming | Schutz und Hardening, 6-Phasen-Pipeline (Assess → Verify), Greenbone-Anbindung, Remediation mit Vorher/Nachher-Evidence |
| **Yellow Queen** | Yellow Reverse-Teaming | Reverse Engineering von Samples (EXE/DLL/APK/ELF/HEX), 6-stufige RE-Pipeline mit begründeten Schritten |

Zusammenspiel: **Red** belegt den Angriffspfad, **Yellow** verifiziert offline, **Blue** behebt, testet erneut und dokumentiert.

| Rote Königin | Blaue Königin | Gelbe Königin |
|---|---|---|
| ![Rote Königin, Render des 3D-Modells](docs/screenshots/queen-red.png) | ![Blaue Königin, Render des 3D-Modells](docs/screenshots/queen-blue.png) | ![Gelbe Königin, Render des 3D-Modells](docs/screenshots/queen-yellow.png) |

*Echte Renders der 3D-Modelle aus `antbb/web/static/brain/queen-viewer.js` (WebGL).*

Gemeinsame Leitplanken aller Teams (Scope default-deny, Human Oversight, Proof-Gate, Honest-empty, defensiv als Standard, nicht-destruktiv finden und belegen): siehe [Leitplanken und Sicherheitsmodell](#leitplanken-und-sicherheitsmodell).

## Red Queen – Offensive Sicherheit

Route `/red`. 18 Soldaten mit Playbooks, Tools und abhakbaren Aufgaben.

![Seitenkopf der Red Queen](docs/images/red-queen.png)

![Ansicht der Red Queen](docs/screenshots/shot-heute-red.jpg)

**Funktionen**

- **Statistiken:** Soldaten, Playbooks, Aufgaben, Findings, Ziele, Scope-Einträge. Echte Werte aus der Registry.
- **Phasen-Pipeline:** Recon, Vulnerability Assessment, Exploitation, Post-Exploitation, Reporting (defensiv oder offensiv gekennzeichnet).
- **Red-Team-Menü** (nach Zielauswahl): Recon und OSINT, Schwachstellen-Scan, Aktive Verifikation (Oversight), PoC aus Evidence (Oversight), LLM-Security, Reporting. Jeder Klick legt einen echten Lauf an.
- **Ziele und Scope-Manager:** Ziele anlegen (Name, Beschreibung, `mode_policy`), Scope-Einträge, Oversight-Status, Archivieren (`/trash`), Undo der letzten Scope- oder Target-Änderung. Undo setzt nie Oversight.
- **Findings:** über alle Ziele, nach Schwere sortiert. „In Blau reparieren“ erzeugt einen echten Remediate-Job in `/blue`.
- **Fernzugriff:** lokal, Tailscale oder Cloudflare-Tunnel. Start nur mit Oversight-Bestätigung.

**Orchestrierung eines Laufs** (`antbb/web/app.py`, `antbb/service.py`)

1. Ziel anlegen und Scope-Einträge pflegen (`/target/add`, `/target/{id}`).
2. Oversight für das Ziel bestätigen (`POST /target/{id}/oversight`).
3. Kolonie starten: Scan-Tiefe *Leicht* (recon, scan, report) oder *Intensiv* (alle Phasen). Aktive beziehungsweise offensive Schritte nur mit zusätzlichem Oversight-Häkchen.
4. Der Lauf startet als Hintergrund-Thread (`_start_scan_async` ruft `svc.run_scan`). Es läuft immer nur ein Scan gleichzeitig, sonst HTTP 409. Fehlt Oversight, endet der Lauf mit Status `error`.
5. Ereignisse erscheinen im Live-Feed. Nach Abschluss werden Schwere-Verteilung, Findings und der Run-Eintrag in der Historie gespeichert.

### Funk-Labor (`/wlan`)

WLAN-Scope (Allowlist), Coverage und Scan (passiv und Königin-Voll-Scan mit rein defensiven Checks), Heatmap, Offensiv/Airgorah sowie Bluetooth/BLE- und IoT-Lab-Karten.

![WLAN, Bluetooth und IoT im Funk-Labor](docs/screenshots/shot-wlan.jpg)

**Späher:** Im Tab *Coverage & Scan* zeigt `/wlan` den WLAN-Späher als 3D-Modell (`queen-viewer.js`, Modell `archer.glb`) neben dem Königin-Voll-Scan und den erkannten Geräten. Ohne WebGL erscheint statt des Modells nur der Text-Hinweis „WebGL nicht verfügbar“.

| Späher |
|---|
| ![Render des Späher-Modells archer.glb](docs/screenshots/scout.png) |

*Echter Render des Späher-Modells (`archer.glb`) aus `queen-viewer.js`, im selben Stil wie die Königinnen.*

![WLAN-Späher auf der Seite /wlan](docs/images/wlan-scout.png)

Erkannte Geräte im Funk-Labor:

![Erkannte Geräte im Funk-Labor](docs/screenshots/shot-heute-wlan.jpg)

| Tab | Bild |
|---|---|
| Coverage und Scan | ![Tab Coverage und Scan](docs/screenshots/shot-wlan-coverage.jpg) |
| Heatmap | ![Tab Heatmap](docs/screenshots/shot-wlan-heatmap.jpg) |
| Offensiv/Airgorah | ![Tab Offensiv und Airgorah](docs/screenshots/shot-wlan-offensive.jpg) |

- **Gates im Funk-Labor:** Passive Coverage-Scans brauchen kein Engagement. Die Client-Abfrage verlangt eine Oversight-Bestätigung. Offensive Aktionen brauchen Engagement-Gate, Oversight und `ANTBB_WIFI=1`.
- **Offensiv/Airgorah:** an [Airgorah](https://github.com/martin-olivier/airgorah) (MIT) angelehnte, web-native Audit-Schicht (`antbb/wlan_airgorah.py`): Interface- und Monitor-Mode-Status, AP- und Client-Liste, Handshake/PMKID, gezielter Deauth, Offline-Crack. Kein Airgorah-Code eingebettet. Scharfe Aktionen nur über `wlan_offensive` mit Engagement-Gate, Oversight und `ANTBB_WIFI=1`. Keine autonomen Ketten.
- **Bluetooth/BLE** (passiv): Inventar, GATT-Lesekarte, Verbindungs-Tracking. Verifikation nur an eigenen Geräten mit Oversight.
- **IoT-Lab** (eigene Geräte): Inventar (FritzBox/mDNS/SSDP), MQTT-Audit, Zigbee/Z-Wave-Karte, Default-Credential-Check. Kette Red, Yellow, Blue.

### Reports (Red, zielbezogen)

- `GET /target/{id}/branded-report` – gebrandeter HTML-Report (Firma, Logo, Farbe, Titel, Kunde als Parameter).
- `GET /target/{id}/report/print` – druckoptimierte Ansicht (Browser: Drucken, Als PDF).
- `GET /target/{id}/report.pdf` – PDF-Download über weasyprint oder wkhtmltopdf. Ohne Engine ehrlicher HTML-Fallback.
- `GET /report/{id}/view` und `GET /report/{id}/export?format=md|json` – Markdown-Ansicht beziehungsweise Export nach `data/exports/`. Addenda und Revisionen über `/report/{id}/addendum` und `/report/{id}/revisions`.

## Blue Queen – Schutz und Hardening

Route `/blue`. 25 Soldaten (Greenbone, Hardening, Watcher, AV/ClamAV, Remediation, Re-Check).

> **Betriebsstand (Bestandsaufnahme 01.11.2026):** Greenbone ist eingebaut. Auf dem Referenz-Laptop läuft der Dienst aber nicht (`gvmd`, Socket und `python-gvm` fehlen). Der Report-Import aus Datei funktioniert. Der ClamAV-Scan ist echt. `freshclam` und `clamd` laufen dort nicht als Dienst. Canary und Fallen sind echt, lauschen aber nur auf Loopback und sind flüchtig.

![Seitenkopf der Blue Queen](docs/images/blue-queen.png)

![Ansicht der Blue Queen](docs/screenshots/shot-heute-blue.jpg)

- **Phasen-Pipeline:** Assess, Watch, Harden, Defend, Remediate, Verify.
- **Kolonie starten** (`POST /api/blue/run`): *Leicht* ist Assess und Harden, *Intensiv* sind alle Phasen. Read-only per Default. Aktive Fixes (`apply_fixes`) nur mit Oversight, sonst HTTP 403.
- **Greenbone/OpenVAS:** Report-Import (XML, CSV, JSON, rein lesend) und Scoped Scan auf einen In-Scope-Host. Oversight ist Pflicht. Ohne GVM ein ehrlicher HTTP 503.
- **Jobs:** wiederholbare Checks (Software-Scan, Hardening, Remediation-Verify) mit Intervall und manuellem Auslösen.
- **Posture-Ledger:** Vorher/Nachher über Läufe. „Nachweislich geschlossen“ nur mit Re-Check.
- **Attack-Log** (append-only), **Posture/SIEM** (optional Splunk HEC), **Remediation** (Fix-Brücke aus Red; ohne Target-Oversight HTTP 403), **Blue-Läufe**.

## Yellow Queen – Reverse Engineering

Route `/yellow`. 9 RE-Soldaten (triage, pe, dotnet, android, elf, hex, carve, dos, dynamic), Ghidra und ghidra-mcp.

> **Betriebsstand:** Die normale Fall-Pipeline ist echt (`file`, `strings`, `readelf`, `rizin`, Live-JSONL). Orchestrate-Schritte lesen den Fallordner `CASES_DIR/<id>` inklusive `evidence/sample.bin` (früher fälschlich `DATA_DIR/cases`). `analyzeHeadless` wird aufgerufen, wenn Ghidra installiert ist. Fehlen `capa` oder `floss`, bleibt das Ergebnis ehrlich leer.

![Seitenkopf der Yellow Queen](docs/images/yellow-queen.png)

![Ansicht der Yellow Queen](docs/screenshots/shot-heute-yellow.jpg)

- **RE-Pipeline:** Triage (Hex, Strings, Sektionen), Identifikation (diec), Entpacken (Lab, Oversight), Static (Ghidra), Dynamic (Frida-Lab, Oversight), Dossier.
- **Analyse starten:** Sample-Upload (EXE, DLL, SYS, APK, SO, ELF, BIN, HEX und weitere) nur mit bestätigter Autorisierung. Dynamic-Lab nur mit Oversight.
- **Orchestrierung** (`yellow-queen/queen/orchestrator.py`): Fall anlegen, erst nach bestandenem Autorisierungs-Gate, dann klassifizieren, Toolchain wählen, Soldaten ausführen, Ergebnisse in Dossier, Ledger und Neuronales Gehirn zusammenführen. Jeder Hop wird begründet. Die nächsten drei Schritte werden aus echten Funden abgeleitet.
- **Fälle** (`/yellow/case/{id}`, `/yellow/laeufe`): Hops, Next-3, Funde mit Adresse, Evidence-Links. Je Fall `ledger.md` und `dossier.md` im Fallordner.
- **Tool-Doctor:** Werkzeugstatus (Ghidra, diec, Frida und weitere) mit Pfad und Zweck.

## Gemeinsame Bereiche

### Hub (`/`)

Einstieg mit den drei Königinnen-Karten, Live-Status aus der Colony und Rechtshinweis.

![Hub mit den drei Königinnen](docs/screenshots/shot-hub.jpg)

### Neuronales Gehirn (`/brain`)

Das Neuronale Gehirn speichert das Wissen der Plattform und zeigt es als 3D-Ameisenstadt: die Rote Königin auf dem Thron in der Mitte, die Blaue Königin in ihrem Wachviertel, die Gelbe Königin in ihrer Schmiede. Die Namensschilder folgen den echten 3D-Positionen. Die Stadt ist drehbar. Die roten und blauen Soldaten-Schilder stammen live aus `/api/soldiers`, die gelben aus der statischen `YELLOW`-Liste in `antbb/web/static/brain/ants3d.js`. Ohne WebGL zeigt die Ansicht nur einen Text-Hinweis. Dazu Knoten-Panel mit Logs, Zeitraffer und Schwarm-Wiki (WER, WAS, WIE, WO, WARUM). Aliasse: `/red/brain`, `/blue/brain`, `/yellow/brain`.

![Neuronales Gehirn, Übersicht der Stadt](docs/screenshots/shot-brain.jpg)

![Neuronales Gehirn, Thron der Roten Königin](docs/images/brain-city-capital.png)

### Historie (`/history`)

Persistente Run-Historie aller Teams mit Zeitraffer sowie Export-Index (`GET /api/exports`, Download über `/exports/{name}` aus `data/exports/`).

![Run-Historie aller Teams](docs/screenshots/shot-history.jpg)

### Reports (alle Teams)

Feste Ablage je Königin unter `data/reports/<red|blue|yellow>/` (gitignored, da echte Befunde). Pro Lauf beziehungsweise Fall entsteht ein HTML-Report und, mit weasyprint oder wkhtmltopdf, ein PDF (`antbb/report_store.py`, nutzt die bestehende Report-Logik). Die PDF-Abhängigkeiten stehen in [requirements-report.txt](requirements-report.txt).

| Team | Quelle | Erzeugen |
|---|---|---|
| Red | gebrandeter Ziel-Report (`brandedreport`) | `POST /api/reports/generate` mit `{"queen":"red","target_id":…}` |
| Blue | Lauf aus der Run-Historie und Ziel-Findings | `{"queen":"blue","run_id":…}` |
| Yellow | `dossier.md` und `ledger.md` des Falls | `{"queen":"yellow","case_id":…}` |

Übersicht und Erzeugen-Formular: `GET /reports`. Liste als JSON: `GET /api/reports`. Download: `GET /reports/<queen>/<datei>` (Dateinamen per Whitelist, Pfad per `resolve()` geprüft). In der Historie hat jeder Lauf einen PDF-Button.

### Weitere Routen

| Route | Inhalt |
|---|---|
| `/target/{id}` | Ziel-Detail: Scope, Oversight, Mode, Findings, Reports, Scan-Status |
| `/target/add` | Ziel anlegen |
| `/assets` | Eigene Assets (TLS- und Header-Checks) |
| `/trash` | Archivierte Ziele, wiederherstellbar |

## Architektur

Ein Prozess, ein Port (`:1001`), drei eingebettete Apps:

```text
antbb.service (python -m api, WorkingDirectory=/opt/antbb)
├── /                Hub          → Next.js-Static-Export (all-and-one/out)
├── /red /blue       Kolonie      → antbb.web (FastAPI)
├── /yellow …        Yellow Queen → yellow_queen.web (FastAPI, RE-Orchestrierung)
├── /brain           Neuronales Gehirn → Colony-Brain
├── /wlan /assets /history …     → Colony-Routen
└── /api/…           Queens-APIs, Targets, Runs, Feed, Capabilities, Blue-Jobs
```

- **Eine Adresse, same-origin:** alle Seiten und APIs hinter `http://127.0.0.1:1001`. Kein CORS, kein Sidecar-Zwang.
- **Echte Daten nur:** keine Mocks im Endprodukt. Jede Zahl kommt aus Registry, Store oder Tool-Ausgabe.
- **Statik:** `/static` merged aus Colony- und Yellow-Static. Der Hub liefert aus `all-and-one/out`.

## Installation

Der vollständige Erststart (Benutzer `antbb`, Hash, Dienst, Loopback) steht im [Schnellstart](#schnellstart). Dieser Abschnitt ergänzt Voraussetzungen, das KI-Menü, den Hub-Build und die Prüfung. Er wiederholt keine zweite, abweichende Startprozedur.

Voraussetzungen: **Linux** (getestet auf Debian/Ubuntu), **Python 3.11 oder neuer**, **Node.js 20 oder neuer** (nur für den Hub-Build), git. WLAN-Features brauchen eine WLAN-Karte mit Monitor-Modus. Greenbone ist optional.

### 1. Klonen und Umgebung

Für einen lokalen Checkout ohne systemd, nicht als Ersatz für `/opt/antbb`:

```bash
git clone https://github.com/krockodog/antbb-framework.git
cd antbb-framework
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 2. Konfiguration

```bash
cp antbb.env.example antbb.env   # chmod 600, niemals committen
chmod 600 antbb.env
```

`antbb.env` ist gitignored. Der Passwort-Hash darin ist Pflicht, sobald der Prozess starten soll. Erzeugen, aus dem Checkout heraus:

```bash
.venv/bin/python -m antbb.webauth hash-password
```

Die ausgegebene Zeile als `ANTBB_ADMIN_PASSWORD_HASH=` in `antbb.env` eintragen. Details der Unit-Installation: [DEPLOY.md](DEPLOY.md).

Beim ersten `./run.sh` erscheint ein KI- und Zugangs-Menü:

1. **Eigene KI (API-Key).** MiniMax (Pflicht-Angebot), Claude, ChatGPT, Gemini, Qwen, Mistral. Edition Free.
2. **Ollama.** Lokale KI ohne Cloud-Key. Edition Free.
3. **OAuth-Login.** Identifikation, danach die Plan-Version mit erweiterten Features.
4. **Enter.** Ohne KI weiter. Edition Free.

Gespeichert in `antbb.env`: `ANTBB_AI_MODE`, `ANTBB_EDITION=free|plan`, Provider und Keys. Ablauf des Menüs: [INSTALL.md](INSTALL.md).

Weitere optionale Variablen, mit tragfähigen Defaults: `ANTBB_HOST`, `ANTBB_PORT`, `COLONY_DB`, `COLONY_DATA`, `YELLOW_QUEEN_ROOT`, `ANTBB_WIFI=1`, `GVM_USERNAME`, `GVM_PASSWORD`, `ANTBB_SPLUNK_HEC_URL`, `ANTBB_SPLUNK_HEC_TOKEN`, `MINIMAX_API_KEY` (nur zur Laufzeit).

### 3. Hub bauen (Next.js Static Export)

```bash
cd all-and-one
npm ci
npm run build          # erzeugt out/
rm -f out/*.txt        # RSC-Payload-Dateien nicht ausliefern
cd ..
```

`all-and-one/out` ist der Webroot für `/`. Die Unit setzt dafür `ALLONE_WEB_ROOT=/opt/antbb/all-and-one/out`.

### 4. Starten

Dienst und Direktstart stehen im [Schnellstart](#schnellstart): `systemctl enable --now antbb`, oder `python -m api --host 127.0.0.1 --port 1001` als User `antbb`, mit gesourcter `antbb.env`.

> **Passwort.** Ohne `ANTBB_ADMIN_PASSWORD_HASH` oder `ANTBB_ADMIN_PASSWORD` startet nichts. Es gibt kein Default-Passwort.
>
> **Nicht root.** `User=antbb`. Ein Start als root wird verweigert. `ANTBB_ALLOW_ROOT=1` loggt nur eine Warnung und ist kein unterstützter Betrieb.
>
> **Localhost.** Der Bind bleibt `127.0.0.1`. Eine andere Schnittstelle braucht `ANTBB_EXPOSE=1` und schreibt eine Warnung.
>
> **Fernzugriff.** SSH-Tunnel (`ssh -L 1001:127.0.0.1:1001 <user>@<host>`), nicht ein veröffentlichter Port.

`./run.sh` bleibt der zweite Starter auf Port 8000. Es ist nicht derselbe Prozess wie `antbb.service` auf Port 1001.

### 5. Verifizieren

```bash
curl -s http://127.0.0.1:1001/api/health
# {"ok": true, "service": "all-and-one", "queen_ids": ["red","blue","yellow"]}
```

`GET /api/health` braucht keine Sitzung. Alles andere verlangt Login unter http://127.0.0.1:1001/login. Danach: Hub, Königin wählen, Ziel anlegen, Scope pflegen, Oversight, Kolonie starten.

> **Installer.** [`install.sh`](install.sh) kennt `--doctor`, `--noninteractive`, `--install-tools` und `--dry-run`. Ein Schalter `--full` existiert dort nicht. Zusätzliche Pentest-Werkzeuge und Wortlisten holt `ANTBB_FULL=1 bash install-and-start.sh`. Rückfragen überspringt `ANTBB_NONINTERACTIVE=1` oder `ANTBB_ASK_KEY=0`.

## Betrieb

- **Läufe starten:** Ziel im Scope-Manager anlegen, Scope-Einträge setzen, Oversight bestätigen, Kolonie starten. Lesend per Default. Aktiv oder offensiv nur mit Häkchen.
- **Scan-Tiefe:** *Leicht* (recon, scan, report) oder *Intensiv* (alle Phasen). Die Wahl landet im Start-Request und im Log.
- **Fix-Brücke:** Red-Finding, „In Blau reparieren“, echter Remediate-Job in `/blue`.
- **Backups:** Vor Patches legt die Plattform `*.bak-<zeitstempel>` an. DB-Backup vor „Alles löschen“ im Gehirn.
- **Logs:** `journalctl -u antbb -f`.
- **Bind und Konto:** der Dienst aus dem Schnellstart hört auf `127.0.0.1:1001` als User `antbb`. Daran ändert der Betrieb nichts.

## Leitplanken und Sicherheitsmodell

1. **Default-deny Scope.** Leer heißt: kein Ziel, kein Lauf.
2. **Human Oversight.** Aktive Schritte (Deauth, PoC, Fixes, Scans gegen Ziele, Tunnel) brauchen ein gesetztes Häkchen. Der Rechtshinweis ersetzt es nicht.
3. **Proof-Gate.** „Verifiziert“ gilt erst mit Nachweis. Findings ohne Evidence bleiben Verdacht.
4. **Honest-empty.** Was nicht geht, wird ehrlich als Ergebnis gemeldet. Kein erfundener Status.
5. **Keine Secrets und keine PII** in Findings oder Reports. Geknackte Passwörter werden maskiert, nie persistiert.
6. **Defensiv als Standard.** Lesende Prüfungen laufen, ohne die Plattform in einen offensiven Modus zu schalten.
7. **Nicht-destruktiv finden und belegen.** Ein Fund wird gezeigt und belegt, nicht ausgenutzt, um das Ziel zu beschädigen.
8. **Recht.** Hinweis auf § 202a–c StGB und den CFAA auf jeder Seite. Nur autorisierte Ziele, nur eigene Geräte, nur eigene Netze.

## Roadmap

Offene Punkte, noch nicht umgesetzt:

- **Yellow:** Der Fallordner-Pfad ist korrigiert (`CASES_DIR/<id>/evidence/sample.bin`). `analyzeHeadless` wird aufgerufen, wenn die Binärdatei vorhanden ist. Auf dem Referenzsystem fehlen `capa` und `floss`; das Ergebnis bleibt dann ehrlich leer.
- **Persistenter Honeypot** mit Speicherung in `attack_events`.
- **Manipulationssicheres Audit-Log** (`/audit`).
- **Greenbone-Dienst** betriebsbereit machen (`gvmd`, `python-gvm`).
- **Watcher-Event-Quelle** (auditd) für die Blue Queen.
- **3D-Gebäude je Wissensstufe:** Die Ausbaustufe wird bereits berechnet und angezeigt. Die passenden Gebäude in der 3D-Stadt fehlen noch.
- **Schaufenster- und Demo-Version ohne Backend:** statische Vorschau der Oberfläche ohne laufenden Server.
- **Echte Yellow-Soldaten-Daten:** Die gelben Schilder im Neuronalen Gehirn kommen derzeit aus einer statischen Liste in `ants3d.js` statt aus der API.
- **MiniMax M-Plan-Key:** Unterstützung des Abo-Schlüssels zusätzlich zum Pay-as-you-go-Key.
- **Blue-Remediation pro Befund:** gezielte Behebung und Re-Test je einzelnem Finding.
- **Echte Executor an `/api/queens/{q}/runs`:** Läufe über diese Route an reale Ausführung anbinden.

## Credits

| Beteiligte | Rolle |
|---|---|
| Judith Pilarski ([@krockodog](https://github.com/krockodog)) | Konzept, Architektur, Oversight, Maintainerin |
| Cursor ([@cursoragent](https://github.com/cursoragent)) | KI-gestützte Entwicklung |
| lordix | Commits aus der lokalen Entwicklungsumgebung |
| Red Queen (Plattform-Identität) | Commits zu Scan-Tools und Neuronalem Gehirn |
| Kimi Work | Commit „All and One: kompletter Stand 2026-10-25“ |

Grundlage ist die Autorenliste aus `git log`.

## Lizenz und Hinweis

Siehe [LICENSE](LICENSE). Dieses Framework ist für **autorisierte Sicherheitstests, eigene Labore und Aufklärungsarbeit** gebaut. Missbrauch gegen fremde Systeme ist strafbar und technisch durch das Scope-Gate ausgeschlossen. Tricks kennen heißt schützen können.
