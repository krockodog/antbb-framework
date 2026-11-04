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

The web UI binds to **127.0.0.1** only. Another interface needs `ANTBB_EXPOSE=1` and logs a warning. The process refuses to start as root and refuses to start until `ANTBB_ADMIN_PASSWORD_HASH` is set (no default password; `python -m antbb.webauth hash-password`). On a TTY the installer asks once and stores only the hash in `antbb.env` (chmod 600).

## KI-/Zugangs-Menü beim Start (interaktiv)

`./run.sh` / `install-and-start.sh` fragt:

| Wahl | Bedeutung | Edition |
|---|---|---|
| **[1] Eigene KI (API-Key)** | Nur gängige Groß-Modelle: **MiniMax** (Pflicht-Angebot), Claude, ChatGPT, Gemini, Qwen, Mistral | Free |
| **[2] Ollama** | lokale Null-Euro-KI; optional kleines Modell pullen | Free |
| **[3] OAuth-Login** | Identifikation über verdrahtete OAuth-Flows (OpenAI Sign-in, Kimi Device-Code). **→ Plan-Version** mit erweiterten Features | **Plan** |
| **Enter** | ohne KI weiter | Free |

Wahl landet in `antbb.env` (`chmod 600`, gitignored): `ANTBB_AI_MODE`, `ANTBB_EDITION=free|plan`, ggf. `ANTBB_LLM_PROVIDER` / `ANTBB_OAUTH_PROVIDER`, Keys, `OLLAMA_BASE_URL`. Keine Secrets im Repo; OAuth-Tokens verschlüsselt in `data/oauth_tokens.enc`.

Google-/GitHub-Identity als Plattform-Login braucht deine eigene OAuth-App-Client-ID in `antbb.env` — wir hardcoden keine Client-Secrets.

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
