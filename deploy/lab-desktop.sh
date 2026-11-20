#!/bin/sh
# Start a loopback-only Xvfb + Openbox + x11vnc + noVNC desktop for GUI
# tools (Maltego, Burp once installed). Does not listen on public interfaces.
# Judith must set the VNC password herself first:
#   mkdir -p "$HOME/.vnc"
#   vncpasswd "$HOME/.vnc/passwd"
# Then:
#   /opt/antbb-tools/bin/lab-desktop start
# SSH tunnel from her laptop (no public ports):
#   ssh -i ~/.ssh/oracle_antbb -L 6080:127.0.0.1:6080 ubuntu@92.5.88.216
# Open http://127.0.0.1:6080/vnc.html in a local browser.
set -eu
DISPLAY_NUM="${LAB_DISPLAY:-99}"
export DISPLAY=":${DISPLAY_NUM}"
VNC_PORT="${LAB_VNC_PORT:-5900}"
NOVNC_PORT="${LAB_NOVNC_PORT:-6080}"
PASSWD="${HOME}/.vnc/passwd"
NOVNC_ROOT="/usr/share/novnc"
BIND="127.0.0.1"

need_passwd() {
  if [ ! -f "$PASSWD" ]; then
    echo "No VNC password file at $PASSWD." >&2
    echo "Set one yourself (this script will not invent or print a password):" >&2
    echo "  mkdir -p \"$HOME/.vnc\" && vncpasswd \"$HOME/.vnc/passwd\"" >&2
    exit 1
  fi
}

start() {
  need_passwd
  if ss -lptn 2>/dev/null | grep -q "${BIND}:${NOVNC_PORT}"; then
    echo "noVNC already listening on ${BIND}:${NOVNC_PORT}"
    return 0
  fi
  Xvfb "$DISPLAY" -screen 0 1600x900x24 -ac -nolisten tcp >/tmp/lab-xvfb.log 2>&1 &
  sleep 0.5
  openbox >/tmp/lab-openbox.log 2>&1 &
  # x11vnc: localhost only, password file, no built-in http
  x11vnc -display "$DISPLAY" -rfbauth "$PASSWD" -rfbport "$VNC_PORT" \
    -localhost -listen "$BIND" -forever -shared -noxdamage \
    >/tmp/lab-x11vnc.log 2>&1 &
  sleep 0.3
  websockify --web "$NOVNC_ROOT" "${BIND}:${NOVNC_PORT}" "${BIND}:${VNC_PORT}" \
    >/tmp/lab-novnc.log 2>&1 &
  sleep 0.3
  echo "Desktop ready on DISPLAY=$DISPLAY"
  echo "VNC  ${BIND}:${VNC_PORT} (loopback only)"
  echo "noVNC ${BIND}:${NOVNC_PORT} (loopback only)"
  echo "Tunnel: ssh -L ${NOVNC_PORT}:${BIND}:${NOVNC_PORT} ubuntu@92.5.88.216"
  ss -lptn | grep -E "${VNC_PORT}|${NOVNC_PORT}" || true
}

stop() {
  pkill -f "websockify --web ${NOVNC_ROOT} ${BIND}:${NOVNC_PORT}" 2>/dev/null || true
  pkill -f "x11vnc -display ${DISPLAY}" 2>/dev/null || true
  pkill -f "openbox" 2>/dev/null || true
  pkill -f "Xvfb ${DISPLAY}" 2>/dev/null || true
  echo "lab-desktop stopped"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  status) ss -lptn | grep -E "${VNC_PORT}|${NOVNC_PORT}" || echo "not running" ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
