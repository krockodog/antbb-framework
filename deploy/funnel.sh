#!/usr/bin/env bash
# Optional alternative to Caddy: Tailscale Funnel -> 127.0.0.1:1001.
#   deploy/funnel.sh on | off | status | url
# Syntax per https://tailscale.com/kb/1311/tailscale-funnel (client >= 1.52).
set -euo pipefail
PORT="${ANTBB_PORT:-1001}"
command -v tailscale >/dev/null || { echo "tailscale not installed: https://tailscale.com/download/linux" >&2; exit 1; }
case "${1:-status}" in
  on)
    curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null || { echo "antbb is not answering on 127.0.0.1:$PORT" >&2; exit 1; }
    sudo tailscale funnel --bg "$PORT"
    sudo tailscale funnel status ;;
  off)
    sudo tailscale funnel --https=443 off || sudo tailscale funnel reset
    sudo tailscale funnel status || true ;;
  status)
    sudo tailscale funnel status ;;
  url)
    tailscale status --json | python3 -c 'import json,sys; print("https://" + json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))' ;;
  *) echo "usage: $0 on|off|status|url" >&2; exit 2 ;;
esac
