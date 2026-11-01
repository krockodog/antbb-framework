#!/usr/bin/env bash
# =============================================================================
# All and One - RED-BLUE-Yellow-Ant-Team  ·  install.sh
# Lokaler Installer fuer das antbb-framework-Layout:
#   clone  ->  ./install.sh  ->  lokaler Start
#
# Drei Koeniginnen unter einem Dach:
#   Red    = Pentest / Bug-Bounty
#   Blue   = Schutz / Hardening
#   Yellow = Reverse Engineering
# mit gemeinsamem Neural Brain.
#
# Was dieses Skript tut:
#   1) DOCTOR/PREFLIGHT  — Python/venv/pip + Toolchain je Koenigin pruefen.
#   2) TOOLS (optional)  — fehlende System-Tools je Koenigin nachziehen.
#   3) AI-SETUP          — Mehrfachauswahl: pro Koenigin EIN Anbieter (9 Provider).
#   4) SKILLS/PLAYBOOKS  — Builtins + eigene CRUD-Verzeichnisse je Koenigin.
#   5) START             — venv + deps + Web-GUI (via install-and-start.sh).
#
# Robustheit: KEIN globales set -e. Optionale Schritte scheitern nie den Lauf.
# Secrets NUR zur Laufzeit in antbb.env (chmod 600) — nie ins Repo/Log.
# =============================================================================
set -o pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT" || { printf 'FATAL: cd ROOT fehlgeschlagen\n' >&2; exit 1; }

HOST="${ANTBB_HOST:-127.0.0.1}"
PORT="${ANTBB_PORT:-8000}"
NONINTERACTIVE="${ANTBB_NONINTERACTIVE:-0}"
DOCTOR_ONLY=0
INSTALL_TOOLS="${ANTBB_INSTALL_TOOLS:-0}"
DRY_RUN=0
ENV_FILE="${ROOT}/antbb.env"

usage() {
  cat <<USG
All and One - RED-BLUE-Yellow-Ant-Team · install.sh
  --doctor           Nur Preflight/Doctor-Check, nichts installieren/starten
  --noninteractive   AI-Setup mit Defaults, keine Rueckfragen
  --install-tools    Fehlende System-Tools je Koenigin nachziehen (sudo)
  --dry-run          Alles vorbereiten, aber den Server NICHT starten
  --host H           Bind-Host (Default: ${HOST})
  --port P           Bind-Port (Default: ${PORT})
  -h | --help        Diese Hilfe
Env: ANTBB_HOST, ANTBB_PORT, ANTBB_NONINTERACTIVE=1, ANTBB_INSTALL_TOOLS=1
USG
}

while [ $# -gt 0 ]; do
  case "$1" in
    --doctor) DOCTOR_ONLY=1; shift;;
    --noninteractive) NONINTERACTIVE=1; shift;;
    --install-tools) INSTALL_TOOLS=1; shift;;
    --dry-run) DRY_RUN=1; shift;;
    --host) HOST="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) printf 'Unbekannte Option: %s\n' "$1"; usage; exit 2;;
  esac
done

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ok  %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  !!  %s\033[0m\n' "$*"; }
err()  { printf '\033[1;31m  xx  %s\033[0m\n' "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

# --- Toolchain je Koenigin (nur Namen; Verfuegbarkeit wird geprueft) ---------
RED_TOOLS="nmap httpx nuclei whatweb sslscan"
BLUE_TOOLS="openssl ss ufw sha256sum"
YELLOW_TOOLS="file strings nm objdump readelf radare2 binwalk apktool jadx unzip"
# Optionale Scan-/Report-Tools (Monatslauf-Lücken): PDF-Engine, OOB/OAST, Metasploit.
# Fehlen sie, degradiert antbb EHRLICH (HTML statt PDF, "nur Indikator" statt OOB-Nachweis,
# Skip statt Fake bei msfconsole). Nichts wird vorgetäuscht.
REPORT_TOOLS="wkhtmltopdf"          # Alternative zur Python-Engine weasyprint
OOB_TOOLS="interactsh-client"       # OOB/OAST-Verifikation blinder Funde (SSRF/RCE/XXE)
MSF_TOOLS="msfconsole"              # Metasploit – NUR auxiliary/scanner (hart allowlisted)

check_group() {
  # $1 = Label, $2 = tool list (durch Leerzeichen getrennt) ; MISSING = Anzahl fehlend
  local label="$1" tools="$2"
  local missing=0 present="" t
  say "Doctor · ${label}"
  # bewusste Wort-Trennung der Tool-Liste:
  # shellcheck disable=SC2086
  for t in $tools; do
    if have "$t"; then
      present="${present} ${t}"
    else
      warn "fehlt: ${t}"
      missing=$((missing+1))
    fi
  done
  [ -n "$present" ] && ok "vorhanden:${present}"
  MISSING=$missing
}

doctor() {
  local fatal=0
  say "Doctor · Basis"
  if have python3; then ok "python3 $(python3 -V 2>&1 | awk '{print $2}')"; else err "python3 fehlt (zwingend)"; fatal=1; fi
  if python3 -m venv --help >/dev/null 2>&1; then ok "venv verfuegbar"; else warn "python3-venv fehlt (apt install python3-venv)"; fi
  if python3 -m pip --version >/dev/null 2>&1; then ok "pip verfuegbar"; else warn "pip fehlt (apt install python3-pip)"; fi
  have node && ok "node $(node -v 2>/dev/null)" || warn "node optional (nur fuer UI-Rebuild noetig)"

  check_group "Rote Koenigin (Pentest/Bug-Bounty)" "$RED_TOOLS";    red_missing=$MISSING
  check_group "Blaue Koenigin (Schutz/Hardening)"  "$BLUE_TOOLS";   blue_missing=$MISSING
  check_group "Gelbe Koenigin (Reverse Eng.)"      "$YELLOW_TOOLS"; yellow_missing=$MISSING

  say "Doctor · Scan-/Report-Tools (optional, ehrlicher Fallback)"
  if python3 -c "import weasyprint" >/dev/null 2>&1; then
    ok "PDF-Engine: weasyprint (Python) vorhanden"
  elif have wkhtmltopdf; then
    ok "PDF-Engine: wkhtmltopdf vorhanden"
  else
    warn "keine PDF-Engine (weasyprint/wkhtmltopdf) – Reports fallen ehrlich auf HTML zurueck"
  fi
  if have interactsh-client; then ok "OOB/OAST: interactsh-client vorhanden";     else warn "interactsh-client fehlt – blinde Funde bleiben ehrlich 'nur Indikator'"; fi
  if have msfconsole; then ok "Metasploit: msfconsole vorhanden (nur auxiliary/scanner)";     else warn "msfconsole fehlt – Metasploit-Checks werden ehrlich uebersprungen (kein Fake)"; fi

  say "Doctor · Bilanz"
  printf '  Red fehlend: %s · Blue fehlend: %s · Yellow fehlend: %s\n' \
    "$red_missing" "$blue_missing" "$yellow_missing"
  [ "$fatal" -eq 0 ] && ok "Preflight bestanden (optionale Tools duerfen fehlen)." \
                     || err "Preflight: zwingende Komponente fehlt."
  return "$fatal"
}

install_tools() {
  have apt-get || { warn "apt-get nicht gefunden – System-Tools bitte manuell installieren."; return 0; }
  say "Installiere fehlende System-Tools (sudo apt-get)"
  # shellcheck disable=SC2086
  sudo apt-get update -y && sudo apt-get install -y \
    binutils file radare2 binwalk unzip openssl python3-venv python3-pip \
    || warn "Einige Pakete konnten nicht installiert werden (fortfahren)."

  # --- Scan-/Report-Tools (optional) ---------------------------------------
  # PDF-Engine: weasyprint (Python) braucht System-Bibliotheken (Pango/Cairo).
  say "Optionale PDF-Engine (weasyprint + Systembibliotheken)"
  sudo apt-get install -y \
    libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi-dev \
    || warn "weasyprint-Systembibliotheken unvollstaendig – ggf. wkhtmltopdf nutzen."
  # weasyprint selbst wird ins venv installiert (siehe ensure_venv/requirements).
  # Alternative Engine ohne Python-Deps:
  if ! have wkhtmltopdf; then
    sudo apt-get install -y wkhtmltopdf || warn "wkhtmltopdf optional – uebersprungen."
  fi

  # OOB/OAST: interactsh-client (ProjectDiscovery, Go-Binary).
  if ! have interactsh-client; then
    if have go; then
      say "Installiere interactsh-client via go install"
      GOBIN="${HOME}/.local/bin" go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
        || warn "interactsh-client Go-Build fehlgeschlagen – OOB bleibt 'nur Indikator'."
    else
      warn "interactsh-client fehlt und 'go' ist nicht installiert."
      warn "  Option A: apt-get install -y golang-go && GOBIN=~/.local/bin go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
      warn "  Option B: Release-Binary von https://github.com/projectdiscovery/interactsh/releases nach ~/.local/bin legen."
    fi
  fi

  # Metasploit (msfconsole): grosses Paket; NUR auxiliary/scanner-Module werden genutzt.
  if ! have msfconsole; then
    warn "Metasploit (msfconsole) nicht installiert – Metasploit-Checks werden ehrlich uebersprungen."
    warn "  Kali/Debian:  sudo apt-get install -y metasploit-framework"
    warn "  Sonst:        https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
  fi
}

# --- AI-Setup: pro Koenigin EIN Anbieter (9 Provider) ------------------------
PROVIDERS="openai anthropic gemini minimax moonshot mistral deepseek xai ollama"
# Key-Env je Provider (nur NAMEN; Werte setzt der Nutzer in antbb.env):
key_env_for() {
  case "$1" in
    openai) echo OPENAI_API_KEY;; anthropic) echo ANTHROPIC_API_KEY;;
    gemini) echo GEMINI_API_KEY;; minimax) echo MINIMAX_API_KEY;;
    moonshot) echo MOONSHOT_API_KEY;; mistral) echo MISTRAL_API_KEY;;
    deepseek) echo DEEPSEEK_API_KEY;; xai) echo XAI_API_KEY;;
    ollama) echo "";; *) echo "";;
  esac
}

pick_provider() {
  # $1 = Koenigin-Label, $2 = Default ; Ergebnis in REPLY_PROVIDER
  local label="$1" def="$2" sel="$2"
  if [ "$NONINTERACTIVE" = "1" ]; then REPLY_PROVIDER="$def"; return 0; fi
  printf '\nAnbieter fuer %s waehlen:\n' "$label"
  local i=1
  for p in $PROVIDERS; do printf '  %d) %s%s\n' "$i" "$p" \
    "$( [ "$p" = "$def" ] && printf ' (Default)' )"; i=$((i+1)); done
  printf 'Auswahl [Enter=%s]: ' "$def"
  read -r ans || ans=""
  if [ -n "$ans" ]; then
    i=1; for p in $PROVIDERS; do [ "$i" = "$ans" ] && sel="$p"; i=$((i+1)); done
  fi
  REPLY_PROVIDER="$sel"
}

ai_setup() {
  say "AI-Setup · pro Koenigin EIN Anbieter (9 Provider, frei zuweisbar)"
  pick_provider "Rote Koenigin (Red)"    "anthropic"; red_p="$REPLY_PROVIDER"
  pick_provider "Blaue Koenigin (Blue)"  "ollama";    blue_p="$REPLY_PROVIDER"
  pick_provider "Gelbe Koenigin (Yellow)" "minimax";  yellow_p="$REPLY_PROVIDER"
  ok "Red=${red_p} · Blue=${blue_p} · Yellow=${yellow_p}"

  # antbb.env anlegen/erweitern (Provider-Zuordnung + leere Key-Platzhalter).
  touch "$ENV_FILE"; chmod 600 "$ENV_FILE"
  {
    printf '# All and One · AI-Zuordnung je Koenigin (Werte NICHT committen)\n'
    printf 'ANTBB_QUEEN_RED_PROVIDER=%s\n' "$red_p"
    printf 'ANTBB_QUEEN_BLUE_PROVIDER=%s\n' "$blue_p"
    printf 'ANTBB_QUEEN_YELLOW_PROVIDER=%s\n' "$yellow_p"
    for p in "$red_p" "$blue_p" "$yellow_p"; do
      ke="$(key_env_for "$p")"
      [ -n "$ke" ] && printf '%s=\n' "$ke"
    done
  } >> "$ENV_FILE"
  ok "AI-Zuordnung in antbb.env geschrieben (chmod 600). Keys dort selbst eintragen."
}

# --- Skills/Playbooks: Builtins + eigene CRUD-Verzeichnisse je Koenigin -------
skills_playbooks() {
  say "Skills/Playbooks · Builtins + eigene (CRUD) je Koenigin"
  for q in red blue yellow; do
    mkdir -p "antbb/agents/skills/custom/${q}" "antbb/playbooks/custom/${q}"
  done
  ok "Eigene Skills:    antbb/agents/skills/custom/{red,blue,yellow}/*.md"
  ok "Eigene Playbooks: antbb/playbooks/custom/{red,blue,yellow}/*.(md|json)"
  ok "Hinzufuegen/erstellen/loeschen: einfach Dateien in diesen Ordnern pflegen."
}

# ============================= Ablauf ========================================
say "All and One - RED-BLUE-Yellow-Ant-Team · Installer"
doctor || { err "Preflight fehlgeschlagen – Abbruch."; exit 1; }

if [ "$DOCTOR_ONLY" = "1" ]; then
  ok "Doctor-Only: nichts installiert/gestartet."
  exit 0
fi

[ "$INSTALL_TOOLS" = "1" ] && install_tools
ai_setup
skills_playbooks

if [ "$DRY_RUN" = "1" ]; then
  say "Dry-Run: Setup fertig, Server wird NICHT gestartet."
  ok "Start spaeter mit: ./install-and-start.sh  (oder ./run.sh)"
  exit 0
fi

say "Starte lokal (venv + deps + Web-GUI)"
ANTBB_HOST="$HOST" ANTBB_PORT="$PORT" exec "${ROOT}/install-and-start.sh"
