# antbb – Schnellstart (GitHub-Distribution)

Keyfreie, anonymisierte Version **ohne Secrets und ohne persönliche Daten**.

## Voraussetzungen

- Python **3.11–3.13** (`python3`)
- Internet (einmalig für `pip install`)

## Ein Befehl

```bash
unzip antbb-clean-*.zip -d antbb && cd antbb
bash install-and-start.sh
```

Ausgabe z. B. `Startseite: http://127.0.0.1:8000/`  
`./run.sh` ist ein Wrapper. Port: `ANTBB_PORT=1001 bash install-and-start.sh`

## KI-Menü beim Start (interaktiv)

`./run.sh` / `install-and-start.sh` fragt zuerst:

| Wahl | Bedeutung |
|---|---|
| **[1] Eigene KI** | API-Key für MiniMax, OpenAI, Anthropic, Google/Gemini, Grok/xAI, Kimi, OpenCode oder Custom |
| **[2] Ollama** | lokale Null-Euro-KI — prüft Erreichbarkeit, optional Pull eines kleinen Modells (`llama3.2:1b` / `qwen2.5:1.5b` / `gemma2:2b`) |
| **[3] / Enter** | **ohne KI** weiter — Plattform läuft (UI, Geräte, Scans); nur LLM-Features bleiben inaktiv |

Die Wahl landet in lokaler `antbb.env` (`chmod 600`, gitignored): `ANTBB_AI_MODE=api|ollama|none`, bei Bedarf `ANTBB_LLM_PROVIDER`, `OLLAMA_BASE_URL`, `ANTBB_MAIN_MODEL` / Keys. Es werden **nur** Variablen geschrieben, die du wirklich setzt.

Pro Cloud-Anbieter: API-Schlüssel hier, oder OAuth nur wo verdrahtet (aktuell OpenAI in der GUI). Wo kein OAuth existiert, sagt das Script das ehrlich.

Non-interactive: `ANTBB_ASK_KEY=0 bash install-and-start.sh`

MiniMax-Host: `https://api.minimax.io` — Key nur zur Laufzeit als `MINIMAX_API_KEY`.

## Optional: Scan- und Report-Tools

Fehlen diese Tools, läuft antbb trotzdem – aber **ehrlich degradiert**, nie mit Fake-Ausgabe:

| Tool | Wofür | Ohne Tool | Installation |
|---|---|---|---|
| **weasyprint** (oder `wkhtmltopdf`) | PDF-Reports | Report wird als **HTML** geschrieben | `pip install -r requirements-report.txt` + `apt install libpango-1.0-0 libpangocairo-1.0-0 libcairo2` (oder `apt install wkhtmltopdf`) |
| **interactsh-client** | OOB/OAST-Nachweis blinder SSRF/RCE/XXE | Fund bleibt **„nur Indikator“** | `GOBIN=~/.local/bin go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |
| **msfconsole** (Metasploit) | nur `auxiliary/scanner`-Module (hart allowlisted) | Check wird **übersprungen** | Kali/Debian: `sudo apt install metasploit-framework` |

`bash install.sh --doctor` zeigt, was vorhanden ist; `bash install.sh --install-tools` versucht die Installation.
Scope-Prüfung, Default-Deny und Human Oversight gelten für alle aktiven Tools unverändert.

## Bewusst entfernt

Keine API-Keys/Tokens/Passwörter · keine persönlichen Daten · keine echten Scope-Ziele/Reports/Captures · `data/` startet leer · kein `external/`-Upstream.
