#!/usr/bin/env bash
# Oracle Cloud Always Free (Ampere A1, Ubuntu, arm64): host setup for antbb.
#
#   sudo ANTBB_DOMAIN=antbb.example.org [ACME_EMAIL=you@example.org] deploy/oracle-setup.sh
#
# What it does (idempotent):
#   1. Docker Engine + compose plugin from Docker's official apt repo
#   2. Host firewall: iptables (OCI Ubuntu images use iptables, not ufw).
#      Opens TCP 80 and 443 above the image's final REJECT rule; SSH (22) stays.
#      Persists with netfilter-persistent.
#   3. Caddy from the official apt repo, /etc/caddy/Caddyfile for ANTBB_DOMAIN
#      -> reverse_proxy 127.0.0.1:1001, automatic Let's Encrypt.
# What it does NOT do: OCI Security List (do that in the console, see
# deploy/oracle-free.md), DNS, cloning the repo, writing antbb.env, starting the app.
# No secret is read, written or printed by this script.
set -euo pipefail

DOMAIN="${ANTBB_DOMAIN:-}"
EMAIL="${ACME_EMAIL:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run with sudo"
[[ -n "$DOMAIN" ]] || die "set ANTBB_DOMAIN, e.g. sudo ANTBB_DOMAIN=antbb.example.org $0"
[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$DOMAIN" == *.* ]] || die "ANTBB_DOMAIN looks invalid: $DOMAIN"
[[ -z "$EMAIL" || "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+$ ]] || die "ACME_EMAIL looks invalid"
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || echo "WARN: tested for Ubuntu, found ${ID:-unknown}"
echo "arch: $(dpkg --print-architecture)  (Ampere A1 = arm64)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg debian-keyring debian-archive-keyring apt-transport-https

# --- 1. Docker Engine (https://docs.docker.com/engine/install/ubuntu/) ---
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
  usermod -aG docker "$SUDO_USER" && echo "added $SUDO_USER to group docker (log out/in once)"
fi

# --- 2. Host firewall (iptables; ufw is disabled on OCI Ubuntu images) ---
apt-get install -y iptables-persistent netfilter-persistent
open_port() {
  local port="$1"
  if ! iptables -C INPUT -p tcp -m state --state NEW -m tcp --dport "$port" -j ACCEPT 2>/dev/null; then
    # Insert right above the first REJECT in INPUT (OCI image default), else append.
    local pos
    pos="$(iptables -L INPUT --line-numbers -n | awk '$2=="REJECT"{print $1; exit}')"
    if [[ -n "$pos" ]]; then
      iptables -I INPUT "$pos" -p tcp -m state --state NEW -m tcp --dport "$port" -j ACCEPT
    else
      iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport "$port" -j ACCEPT
    fi
    echo "iptables: opened tcp/$port"
  fi
}
iptables -C INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT 2>/dev/null \
  || die "no SSH ACCEPT rule found in INPUT; refusing to touch the firewall"
open_port 80
open_port 443
netfilter-persistent save
echo "Port 1001 stays closed: the app binds 127.0.0.1 only."

# --- 3. Caddy (https://caddyserver.com/docs/install#debian-ubuntu-raspbian) ---
if ! command -v caddy >/dev/null 2>&1; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y
  apt-get install -y caddy
fi
mkdir -p /var/log/caddy && chown caddy:caddy /var/log/caddy
email_line="no ACME email set"
[[ -n "$EMAIL" ]] && email_line="email $EMAIL"
tmp="$(mktemp)"
sed -e "s|__ANTBB_DOMAIN__|$DOMAIN|g" \
    -e "s|# __ACME_EMAIL_LINE__|$( [[ -n "$EMAIL" ]] && echo "$email_line" || echo "# $email_line")|" \
    "$HERE/Caddyfile.template" > "$tmp"
caddy fmt --overwrite "$tmp" >/dev/null 2>&1 || true
caddy validate --adapter caddyfile --config "$tmp"
[[ -f /etc/caddy/Caddyfile ]] && cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%Y%m%d%H%M%S)"
install -m 0644 "$tmp" /etc/caddy/Caddyfile && rm -f "$tmp"
systemctl enable caddy
systemctl reload caddy || systemctl restart caddy

cat <<MSG

Host setup done for https://$DOMAIN
Next (see deploy/oracle-free.md):
  - DNS: A record $DOMAIN -> public IP of this instance
  - OCI console: Security List ingress TCP 80 + 443 from 0.0.0.0/0
  - antbb.env with ANTBB_ADMIN_PASSWORD_HASH (deploy/make-password-hash.sh), chmod 600
  - docker compose up -d --build
MSG
