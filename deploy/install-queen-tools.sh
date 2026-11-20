#!/bin/bash
# Install antbb queen/OSINT/RE tools from official distro repos and GitHub/vendor releases.
# Intended for the Oracle aarch64 host. Never binds services on 0.0.0.0.
# Aborts if the boot volume would exceed ~85% use.
set -euo pipefail

PREFIX="${ANTBB_TOOLS_PREFIX:-/opt/antbb-tools}"
GHIDRA_ROOT="${GHIDRA_ROOT:-/opt/ghidra}"
BIN="$PREFIX/bin"
DISK_CAP_PCT="${ANTBB_DISK_CAP_PCT:-85}"
ARCH="$(uname -m)"
if [ "$ARCH" != "aarch64" ] && [ "$ARCH" != "arm64" ]; then
  echo "This script targets aarch64 (got $ARCH)." >&2
  exit 1
fi

log() { printf '==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

disk_ok() {
  local pct
  pct=$(df -P / | awk 'NR==2 {gsub("%","",$5); print $5}')
  if [ "$pct" -ge "$DISK_CAP_PCT" ]; then
    echo "Disk use ${pct}% >= ${DISK_CAP_PCT}% — stopping to leave headroom." >&2
    return 1
  fi
  return 0
}

sudo mkdir -p "$BIN" "$PREFIX/src" "$PREFIX/venv" "$GHIDRA_ROOT"
sudo chown -R ubuntu:ubuntu "$PREFIX" "$GHIDRA_ROOT"
export PATH="$BIN:$PATH"

fetch() {
  # fetch <url> <dest> [sha256]
  local url="$1" dest="$2" sha="${3:-}"
  disk_ok
  log "download $(basename "$dest")"
  curl -fL --retry 3 --retry-delay 2 -o "$dest" "$url"
  if [ -n "$sha" ]; then
    echo "$sha  $dest" | sha256sum -c -
  fi
}

github_asset() {
  # github_asset <owner/repo> <regex> -> prints browser_download_url
  local repo="$1" pattern="$2"
  curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
    | python3 -c "import json,re,sys
pat=sys.argv[1]
data=json.load(sys.stdin)
assets=data.get('assets') or []
rx=re.compile(pat, re.I)
for a in assets:
    name=a.get('name') or ''
    if rx.search(name):
        print(a['browser_download_url'])
        print(name, file=sys.stderr)
        sys.exit(0)
print('NO_ASSET', file=sys.stderr)
sys.exit(2)" "$pattern"
}

install_tarball() {
  local url="$1" pattern_bin="$2" name="$3" sha="${4:-}"
  local tmp
  tmp=$(mktemp -d)
  local ext="${url##*/}"
  fetch "$url" "$tmp/$ext" "$sha"
  mkdir -p "$tmp/x"
  case "$ext" in
    *.zip) unzip -q "$tmp/$ext" -d "$tmp/x" ;;
    *.tar.gz|*.tgz) tar -xzf "$tmp/$ext" -C "$tmp/x" ;;
    *.tar.xz) tar -xJf "$tmp/$ext" -C "$tmp/x" ;;
    *) warn "unknown archive $ext"; rm -rf "$tmp"; return 1 ;;
  esac
  local found
  found=$(find "$tmp/x" -type f -name "$pattern_bin" | head -1)
  if [ -z "$found" ]; then
    warn "no $pattern_bin in $name archive"
    rm -rf "$tmp"
    return 1
  fi
  install -m 0755 "$found" "$BIN/$name"
  # some tools ship companion files (jadx)
  rm -rf "$tmp"
  log "installed $name -> $BIN/$name"
}

# ---- Ghidra 12.2 PUBLIC (NSA official, sha256 from release notes) ----
install_ghidra() {
  if [ -x "$GHIDRA_ROOT/support/analyzeHeadless" ]; then
    log "Ghidra already present"
    return 0
  fi
  local zip="/tmp/ghidra_12.2_PUBLIC.zip"
  fetch "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip" \
    "$zip" "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"
  rm -rf "$GHIDRA_ROOT"
  mkdir -p /opt
  sudo mkdir -p /opt
  unzip -q "$zip" -d /tmp/ghidra-unpack
  local unpacked
  unpacked=$(find /tmp/ghidra-unpack -maxdepth 1 -type d -name 'ghidra_*' | head -1)
  sudo rm -rf "$GHIDRA_ROOT"
  sudo mv "$unpacked" "$GHIDRA_ROOT"
  sudo chown -R ubuntu:ubuntu "$GHIDRA_ROOT"
  ln -sfn "$GHIDRA_ROOT/support/analyzeHeadless" "$BIN/analyzeHeadless"
  ln -sfn "$GHIDRA_ROOT/support/analyzeHeadless" "$BIN/ghidra-analyzeHeadless"
  rm -f "$zip"
  rm -rf /tmp/ghidra-unpack
  log "Ghidra installed at $GHIDRA_ROOT"
}

# Official GitHub release binaries (arm64)
install_gh_tool() {
  local repo="$1" pattern="$2" bin="$3"
  if [ -x "$BIN/$bin" ]; then
    log "$bin already present"
    return 0
  fi
  local url
  if ! url=$(github_asset "$repo" "$pattern"); then
    warn "no official arm64 asset for $repo ($pattern)"
    return 0
  fi
  local tmp
  tmp=$(mktemp -d)
  fetch "$url" "$tmp/asset"
  mkdir -p "$tmp/x"
  case "$url" in
    *.zip) unzip -q "$tmp/asset" -d "$tmp/x" ;;
    *.tar.gz|*.tgz|*.tar.xz|*.tar.bz2) tar -xf "$tmp/asset" -C "$tmp/x" ;;
    *)
      if file -b "$tmp/asset" | grep -qi 'zip'; then
        unzip -q "$tmp/asset" -d "$tmp/x"
      elif file -b "$tmp/asset" | grep -Eqi 'tar|gzip|XZcompressed|bzip2'; then
        tar -xf "$tmp/asset" -C "$tmp/x"
      else
        install -m 0755 "$tmp/asset" "$BIN/$bin"
        rm -rf "$tmp"
        log "installed $bin (raw binary)"
        return 0
      fi
      ;;
  esac
  local found
  found=$(find "$tmp/x" -type f -name "$bin" | head -1)
  if [ -z "$found" ]; then
    found=$(find "$tmp/x" -type f -executable | head -1)
  fi
  if [ -n "$found" ]; then
    install -m 0755 "$found" "$BIN/$bin"
    log "installed $bin from $repo"
  else
    warn "could not find $bin in $repo asset"
  fi
  rm -rf "$tmp"
}

log "skip ghidra (already unpacked)"
disk_ok

# ProjectDiscovery + others (official GitHub releases)
install_gh_tool "projectdiscovery/nuclei" 'linux_arm64' nuclei
install_gh_tool "projectdiscovery/httpx" 'linux_arm64' httpx
install_gh_tool "projectdiscovery/subfinder" 'linux_arm64' subfinder
install_gh_tool "projectdiscovery/interactsh" 'linux_arm64' interactsh-client
install_gh_tool "projectdiscovery/dnsx" 'linux_arm64' dnsx
install_gh_tool "ffuf/ffuf" 'linux_arm64' ffuf
install_gh_tool "gitleaks/gitleaks" 'linux_arm64' gitleaks
install_gh_tool "trufflesecurity/trufflehog" 'linux_arm64' trufflehog
install_gh_tool "owasp-amass/amass" 'linux_arm64' amass
install_gh_tool "lc/gau" 'linux_arm64' gau
install_gh_tool "tomnomnom/waybackurls" 'linux_arm64' waybackurls || true
install_gh_tool "mandiant/capa" 'linux_arm64|linux-arm64' capa
install_gh_tool "mandiant/flare-floss" 'linux_arm64|linux-arm64' floss
install_gh_tool "rizinorg/rizin" 'linux-arm64|linux_aarch64|aarch64' rizin || true
install_gh_tool "skylot/jadx" 'jadx-.*\.zip$' jadx
# jadx zip has bin/jadx — install_gh_tool should find it; also copy jadx-gui if present

# Detect It Easy (official horsicq)
install_gh_tool "horsicq/DIE-engine" 'Linux_ARM64|linux_arm64|aarch64' diec || true

# wpscan is a gem — try if ruby is present later
if command -v gem >/dev/null 2>&1; then
  sudo gem install wpscan --no-document || warn "wpscan gem failed"
fi

# Python OSINT / RE venv (official PyPI)
if [ ! -x "$PREFIX/venv/bin/python" ]; then
  python3 -m venv "$PREFIX/venv"
fi
"$PREFIX/venv/bin/pip" install --upgrade pip wheel
# Official packages; skip failures individually
for pkg in sherlock-project maigret holehe theHarvester frida-tools sslyze weasyprint; do
  disk_ok
  "$PREFIX/venv/bin/pip" install --no-cache-dir "$pkg" && log "pip $pkg OK" || warn "pip $pkg failed"
done
for exe in sherlock maigret holehe theHarvester frida frida-ps sslyze; do
  if [ -x "$PREFIX/venv/bin/$exe" ]; then
    ln -sfn "$PREFIX/venv/bin/$exe" "$BIN/$exe"
  fi
done
# theHarvester entry point may be theHarvester or theharvester
if [ -x "$PREFIX/venv/bin/theharvester" ] && [ ! -e "$BIN/theHarvester" ]; then
  ln -sfn "$PREFIX/venv/bin/theharvester" "$BIN/theHarvester"
fi

# Small wordlist for ffuf/gobuster (not full seclists)
mkdir -p "$PREFIX/wordlists"
if [ ! -f "$PREFIX/wordlists/common.txt" ]; then
  # SecLists official raw file (common directory list only, not the whole tree)
  curl -fL --retry 3 -o "$PREFIX/wordlists/common.txt" \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    || warn "common.txt wordlist download failed"
fi

# PATH helper
cat > "$PREFIX/env.sh" << EOF
export PATH="$BIN:$GHIDRA_ROOT/support:\$PATH"
export GHIDRA_INSTALL_DIR="$GHIDRA_ROOT"
export JAVA_HOME="\${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-arm64}"
export YQ_TOOLS_PATH="$BIN:$GHIDRA_ROOT/support"
export ANTBB_WORDLIST="$PREFIX/wordlists/common.txt"
EOF

log "tools prefix ready"
ls -l "$BIN" || true
disk_ok
df -h / | tail -1
