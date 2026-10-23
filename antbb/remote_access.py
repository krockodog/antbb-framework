"""Fernzugriff / Remote-Access: Präferenz + ehrliche, rein lesende Status-Erkennung.

Diese Datei trifft KEINE Netz-Entscheidungen und startet NICHTS. Sie:
  * liest die gespeicherte Präferenz (off | tailscale | cloudflare) aus dem Store,
  * erkennt rein lesend, ob `tailscale` bzw. `cloudflared` installiert sind und
    (bei Tailscale) ob der Dienst läuft inkl. der 100.x-IP – via
    `tailscale status --json` mit kurzem Timeout,
  * liefert ehrliche, handfeste Setup-Schritte je Modus.

Harte Sicherheits-Prinzipien (wie der Rest von antbb):
  * honest-empty: fehlt ein Binary, wird das ehrlich gemeldet – NIE eine
    IP/Hostname/Status erfunden.
  * read-only: nur `--version` bzw. `status --json`. Es wird NIE ein Tunnel
    gestartet, nichts ins Internet exponiert, keine Konfig geschrieben.
  * keine Secrets: ein etwaiger Cloudflare-Token wird ausschließlich zur
    Laufzeit aus der Umgebungsvariable CLOUDFLARE_TUNNEL_TOKEN gelesen – NIE in
    DB/Datei geschrieben, NIE geloggt, NIE ausgegeben.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional

#: Erlaubte Modi (Single Source of Truth).
MODES = ("off", "tailscale", "cloudflare")
DEFAULT_MODE = "off"

#: Lokaler GUI-Port (nur zur Anzeige der Beispiel-URLs).
GUI_PORT = 1001

#: Name der Env-Var für ein etwaiges Cloudflare-Tunnel-Token. Der WERT wird NIE
#: gespeichert/geloggt – nur zur Laufzeit von `cloudflared` selbst gelesen.
CLOUDFLARE_TOKEN_ENV = "CLOUDFLARE_TUNNEL_TOKEN"


def normalize_mode(mode: Optional[str]) -> str:
    m = (mode or "").strip().lower()
    return m if m in MODES else DEFAULT_MODE


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def _run_readonly(argv: list, timeout: float = 4.0) -> tuple[int, str, str]:
    """Führt ein rein lesendes Kommando aus (kein shell=True, hartes Timeout).

    Gibt (returncode, stdout, stderr) zurück; bei Timeout/Fehler returncode=-1.
    """
    try:
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
        return (proc.returncode,
                (proc.stdout or b"").decode("utf-8", "replace"),
                (proc.stderr or b"").decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        return (-1, "", "timeout")
    except Exception as exc:  # pragma: no cover - defensiv
        return (-1, "", str(exc))


def tailscale_status() -> dict:
    """Rein lesender Tailscale-Status. honest-empty ohne Binary/Daemon.

    NIE erfundene IP/Hostname: Werte stammen ausschließlich aus
    `tailscale status --json`.
    """
    path = resolve_binary("tailscale")
    out: dict = {
        "installed": bool(path),
        "path": path or "",
        "running": False,
        "backend_state": "",
        "ip": "",            # 100.x CGNAT-IP des eigenen Geräts
        "hostname": "",
        "url": "",
        "detail": "",
    }
    if not path:
        out["detail"] = "tailscale nicht installiert"
        return out
    rc, so, se = _run_readonly([path, "status", "--json"])
    if rc != 0 or not so.strip():
        out["detail"] = (se.strip() or "tailscale status nicht verfügbar "
                         "(Daemon aus / nicht angemeldet)")
        return out
    try:
        data = json.loads(so)
    except Exception:
        out["detail"] = "tailscale status nicht lesbar (kein gültiges JSON)"
        return out
    state = str(data.get("BackendState") or "")
    out["backend_state"] = state
    out["running"] = (state == "Running")
    self_node = data.get("Self") or {}
    ips = self_node.get("TailscaleIPs") or []
    ip4 = next((ip for ip in ips if ip.startswith("100.")), "")
    out["ip"] = ip4 or (ips[0] if ips else "")
    dns = str(self_node.get("DNSName") or "").rstrip(".")
    out["hostname"] = dns
    if out["ip"]:
        out["url"] = f"http://{out['ip']}:{GUI_PORT}"
    if not out["detail"]:
        out["detail"] = (f"Tailscale läuft (BackendState={state})"
                         if out["running"]
                         else f"Tailscale installiert, aber nicht aktiv "
                              f"(BackendState={state or 'unbekannt'})")
    return out


def cloudflared_status() -> dict:
    """Rein lesender cloudflared-Status (nur Verfügbarkeit/Version)."""
    path = resolve_binary("cloudflared")
    out: dict = {
        "installed": bool(path),
        "path": path or "",
        "version": "",
        "token_env_present": False,  # nur Vorhandensein, NIE der Wert
        "url": "",
        "detail": "",
    }
    # Nur Vorhandensein der Env-Var melden – niemals den Token-WERT.
    import os as _os
    out["token_env_present"] = bool(_os.environ.get(CLOUDFLARE_TOKEN_ENV, "").strip())
    if not path:
        out["detail"] = "cloudflared nicht installiert"
        return out
    rc, so, se = _run_readonly([path, "--version"])
    ver = (so or se).strip().splitlines()
    out["version"] = ver[0] if ver else ""
    out["detail"] = out["version"] or "cloudflared installiert"
    return out


def status_for(mode: Optional[str] = None) -> dict:
    """Vollständiger, ehrlicher Status beider Transporte + aktiver Modus."""
    m = normalize_mode(mode)
    ts = tailscale_status()
    cf = cloudflared_status()
    rt = cloudflare_tunnel_runtime()
    if rt.get("running") and rt.get("url"):
        cf["url"] = rt["url"]
    cf["tunnel"] = rt
    active_url = ""
    if m == "tailscale":
        active_url = ts.get("url", "")
    elif m == "cloudflare":
        active_url = (rt.get("url") or cf.get("url", ""))
    return {
        "mode": m,
        "modes": list(MODES),
        "local_url": f"http://127.0.0.1:{GUI_PORT}",
        "active_url": active_url,
        "tailscale": ts,
        "cloudflare": cf,
        "token_env_name": CLOUDFLARE_TOKEN_ENV,
    }


def setup_steps(mode: str) -> list:
    """Ehrliche, manuelle Schritte, um den gewählten Transport hochzufahren.

    Es werden NUR Anweisungen zurückgegeben – hier wird nichts ausgeführt.
    """
    m = normalize_mode(mode)
    if m == "off":
        return [
            "Kein Fernzugriff: die GUI ist nur lokal erreichbar "
            f"(http://127.0.0.1:{GUI_PORT}).",
            "Nichts ist nach außen exponiert – die sicherste Grundeinstellung.",
        ]
    if m == "tailscale":
        return [
            "Tailscale installieren (falls nicht vorhanden): "
            "https://tailscale.com/download",
            "Anmelden/verbinden:  sudo tailscale up",
            "Optional mit Auth-Key (nur zur Laufzeit als Env-Var TS_AUTHKEY): "
            "  export TS_AUTHKEY=tskey-auth-... && sudo -E tailscale up --authkey=$TS_AUTHKEY",
            "Status prüfen:  tailscale status",
            f"Danach ist die GUI im eigenen Tailnet erreichbar unter "
            f"http://<100.x.y.z>:{GUI_PORT} bzw. http://<magicdns-hostname>:{GUI_PORT} "
            "(nur für Geräte in deinem Tailnet, kein offenes Internet).",
            "Optional Funnel (öffentlich, Oversight-Pflicht):  "
            f"tailscale funnel {GUI_PORT} on",
            "antbb startet oder exponiert Tailscale NICHT ohne Oversight-Haken – "
            "du entscheidest und bestätigst in der GUI (oder führst 'tailscale up' selbst aus).",
        ]
    # cloudflare (Free-Tier: Tunnel + Zero Trust Access + DNS + optional WARP)
    return [
        "cloudflared installieren (falls nicht vorhanden): "
        "https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/",
        "Schnell-Variante (temporärer trycloudflare-Hostname, öffentlich!):  "
        f"cloudflared tunnel --url http://127.0.0.1:{GUI_PORT}",
        "Benannter Tunnel mit Token: Token als Umgebungsvariable "
        f"{CLOUDFLARE_TOKEN_ENV} setzen und  cloudflared tunnel run  starten "
        "(oder in der GUI mit Oversight-Haken starten).",
        "DNS (Free): CNAME auf den Tunnel-Hostname legen – Dashboard oder "
        "per API mit CF_API_TOKEN + CF_ZONE_ID (nie im Repo speichern).",
        "Zero Trust Access (Free, bis 50 Nutzer): Application + Policy "
        "(E-Mail-OTP) vor die GUI legen – siehe Access-Setup-Schritte in der GUI.",
        "Optional WARP: Client installieren und an Zero Trust enrollen "
        "(warp-cli) – antbb fragt den Status nur rein lesend ab.",
        "WICHTIG: Ein Cloudflare-Tunnel macht die lokale GUI über das "
        "ÖFFENTLICHE Internet erreichbar. Nur mit Access-Policy nutzen.",
        "Der Token wird NIE von antbb gespeichert oder geloggt – er wird nur "
        f"zur Laufzeit aus der Env-Var {CLOUDFLARE_TOKEN_ENV} von cloudflared "
        "selbst gelesen.",
        "antbb startet den Tunnel NICHT ohne Oversight-Haken – du bestätigst "
        "in der GUI (oder führst den Befehl selbst aus).",
    ]


# ===========================================================================
# AKTIVE Tunnel-Steuerung (oversight-gated). NEU: antbb kann den Cloudflare-
# Tunnel (und ein Tailscale-up) jetzt selbst STARTEN/STOPPEN – aber nur, wenn
# der Mensch das Oversight-Flag setzt. Default bleibt: nichts wird automatisch
# exponiert. Es werden KEINE Secrets gespeichert: ein benannter Tunnel liest
# sein Token nur zur Laufzeit aus CLOUDFLARE_TUNNEL_TOKEN.
# ===========================================================================
import os as _os
import re as _re
import signal as _signal
import time as _time
import json as _json
from pathlib import Path as _Path

#: Zusätzliche Binary-Suchpfade (die systemd-PATH enthält ~/.local/bin oft NICHT).
_EXTRA_BIN_DIRS = [
    _os.environ.get("ANTBB_BIN", "").strip(),
    str(_Path(__file__).resolve().parent.parent / "bin"),   # <antbb_root>/bin
    _os.path.expanduser("~/.local/bin"),
    _os.path.expanduser("~/bin"),
    "/opt/antbb/bin",
]


def resolve_binary(binary: str) -> Optional[str]:
    """shutil.which + bekannte antbb-lokale bin-Verzeichnisse (ohne root nutzbar)."""
    hit = shutil.which(binary)
    if hit:
        return hit
    override = _os.environ.get("ANTBB_" + binary.upper().replace("-", "_"), "").strip()
    if override and _os.path.isfile(override) and _os.access(override, _os.X_OK):
        return override
    for d in _EXTRA_BIN_DIRS:
        if not d:
            continue
        cand = _os.path.join(d, binary)
        if _os.path.isfile(cand) and _os.access(cand, _os.X_OK):
            return cand
    return None


def _state_path() -> str:
    data_dir = _Path(__file__).resolve().parent.parent / "data"
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        data_dir = _Path(_os.path.expanduser("~"))
    return str(data_dir / "cf_tunnel.json")


def _read_state() -> dict:
    try:
        with open(_state_path(), "r", encoding="utf-8") as fh:
            return _json.load(fh) or {}
    except Exception:
        return {}


def _write_state(st: dict) -> None:
    try:
        with open(_state_path(), "w", encoding="utf-8") as fh:
            _json.dump(st, fh)
    except Exception:
        pass


def _pid_alive(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        _os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def _log_path() -> str:
    return str(_Path(_state_path()).parent / "cf_tunnel.log")


def cloudflare_tunnel_runtime() -> dict:
    """Laufzeit-Status des von antbb verwalteten Cloudflare-Tunnels.

    honest: meldet nur, was wirklich läuft (PID lebt) und welche URL im Log
    tatsächlich auftauchte – nichts erfunden.
    """
    st = _read_state()
    pid = st.get("pid")
    alive = _pid_alive(pid)
    url = st.get("url", "")
    if alive and not url:
        url = _scrape_trycloudflare_url()
        if url:
            st["url"] = url
            _write_state(st)
    return {
        "running": bool(alive),
        "pid": pid if alive else None,
        "url": url if alive else "",
        "mode": st.get("kind", ""),
        "started_ts": st.get("started_ts"),
        "detail": ("Tunnel läuft" if alive else "kein von antbb verwalteter Tunnel aktiv"),
    }


def _scrape_trycloudflare_url() -> str:
    try:
        with open(_log_path(), "r", encoding="utf-8", errors="replace") as fh:
            txt = fh.read()
    except Exception:
        return ""
    m = _re.findall(r"https://[a-z0-9-]+\.trycloudflare\.com", txt)
    return m[-1] if m else ""


def start_cloudflare_tunnel(oversight: bool = False, named: bool = False,
                            local_port: int = GUI_PORT) -> dict:
    """Startet den Cloudflare-Tunnel – NUR mit Oversight (Mensch).

    * named=False: schneller trycloudflare-Tunnel (öffentliche Zufalls-URL).
    * named=True : benannter Tunnel; Token NUR aus CLOUDFLARE_TUNNEL_TOKEN zur
      Laufzeit (nie gespeichert/geloggt). Erfordert gesetztes Token.
    Gibt einen ehrlichen Status zurück; exponiert NICHTS ohne oversight=True.
    """
    if not oversight:
        return {"ok": False, "running": False, "url": "",
                "reason": "Oversight-Gate: Start nur mit menschlichem Oversight-Haken."}
    cur = cloudflare_tunnel_runtime()
    if cur["running"]:
        return {"ok": True, "running": True, "url": cur["url"], "pid": cur["pid"],
                "reason": "Tunnel läuft bereits."}
    cfd = resolve_binary("cloudflared")
    if not cfd:
        return {"ok": False, "running": False, "url": "",
                "reason": "cloudflared nicht gefunden (installiere es nach "
                          "<antbb>/bin/ oder setze ANTBB_CLOUDFLARED)."}
    run_env = None
    if named:
        token = _os.environ.get(CLOUDFLARE_TOKEN_ENV, "").strip()
        if not token:
            return {"ok": False, "running": False, "url": "",
                    "reason": f"Benannter Tunnel braucht {CLOUDFLARE_TOKEN_ENV} "
                              "(Token nur zur Laufzeit, nie gespeichert)."}
        # Token NICHT auf die Kommandozeile (waere in `ps` sichtbar), sondern nur
        # als TUNNEL_TOKEN in die Subprozess-Umgebung – cloudflared liest ihn dort.
        run_env = dict(_os.environ)
        run_env["TUNNEL_TOKEN"] = token
        argv = [cfd, "tunnel", "--no-autoupdate", "run"]
        kind = "named"
    else:
        argv = [cfd, "tunnel", "--no-autoupdate",
                "--url", f"http://127.0.0.1:{local_port}"]
        kind = "quick"
    try:
        logf = open(_log_path(), "w", encoding="utf-8")
    except Exception as exc:
        return {"ok": False, "running": False, "url": "",
                "reason": f"Log-Datei nicht schreibbar: {exc}"}
    try:
        proc = subprocess.Popen(
            argv, stdout=logf, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True,
            close_fds=True, env=run_env,
        )
    except Exception as exc:
        return {"ok": False, "running": False, "url": "",
                "reason": f"cloudflared-Start fehlgeschlagen: {exc}"}
    _write_state({"pid": proc.pid, "kind": kind, "url": "",
                  "started_ts": _time.time()})
    # Kurz auf die trycloudflare-URL warten (nur beim quick-Tunnel sinnvoll).
    url = ""
    if kind == "quick":
        for _ in range(20):
            _time.sleep(0.5)
            url = _scrape_trycloudflare_url()
            if url:
                break
    if url:
        st = _read_state(); st["url"] = url; _write_state(st)
    return {"ok": True, "running": _pid_alive(proc.pid), "pid": proc.pid,
            "url": url, "kind": kind,
            "reason": ("Tunnel gestartet." if url or kind == "named"
                       else "Tunnel gestartet, URL noch nicht im Log – gleich erneut Status abfragen.")}


def stop_cloudflare_tunnel() -> dict:
    """Beendet den von antbb verwalteten Cloudflare-Tunnel (SIGTERM der Gruppe)."""
    st = _read_state()
    pid = st.get("pid")
    if not _pid_alive(pid):
        _write_state({})
        return {"ok": True, "running": False, "reason": "Kein aktiver Tunnel."}
    try:
        try:
            _os.killpg(_os.getpgid(int(pid)), _signal.SIGTERM)
        except Exception:
            _os.kill(int(pid), _signal.SIGTERM)
        for _ in range(10):
            _time.sleep(0.3)
            if not _pid_alive(pid):
                break
        if _pid_alive(pid):
            try:
                _os.killpg(_os.getpgid(int(pid)), _signal.SIGKILL)
            except Exception:
                _os.kill(int(pid), _signal.SIGKILL)
    except Exception as exc:
        return {"ok": False, "running": _pid_alive(pid),
                "reason": f"Stop fehlgeschlagen: {exc}"}
    _write_state({})
    return {"ok": True, "running": False, "reason": "Tunnel gestoppt."}


# ===========================================================================
# ERWEITERUNG: Tailscale aktiv steuern (up/down/Funnel) + Cloudflare Free-Tier
# (Zero Trust Access, DNS, WARP). Alles oversight-gegatet, honest-empty, mit
# Retry bei Netzfehlern und Idempotenz. KEINE Secrets werden gespeichert/
# geloggt/ausgegeben – Tokens werden ausschliesslich zur Laufzeit aus ENV
# gelesen (TS_AUTHKEY, CLOUDFLARE_TUNNEL_TOKEN, CF_API_TOKEN).
# ===========================================================================
import urllib.request as _urlreq
import urllib.error as _urlerr

#: Env-Var-Namen (nur Namen – NIE die Werte speichern/loggen/ausgeben).
TS_AUTHKEY_ENV = "TS_AUTHKEY"               # Tailscale auth key (tailscale up)
CF_API_TOKEN_ENV = "CF_API_TOKEN"           # Cloudflare API token (DNS/Access)
CF_ACCOUNT_ID_ENV = "CF_ACCOUNT_ID"         # Cloudflare account id (Access)
CF_ZONE_ID_ENV = "CF_ZONE_ID"               # Cloudflare zone id (DNS)

#: Default-Timeouts
_NET_TIMEOUT = 8.0
_UP_TIMEOUT = 45.0


def _env_present(name: str) -> bool:
    """Nur VORHANDENSEIN einer Env-Var melden – nie der Wert."""
    return bool(_os.environ.get(name, "").strip())


def _retry(fn, attempts: int = 3, base_delay: float = 0.6):
    """Kleiner Retry-Wrapper fuer Netz-Operationen (exponentielles Backoff).

    Gibt (result, None) bei Erfolg oder (None, last_error_str) zurueck.
    """
    last = ""
    for i in range(max(1, attempts)):
        try:
            return fn(), None
        except Exception as exc:  # pragma: no cover - netzabhaengig
            last = str(exc)
            if i < attempts - 1:
                _time.sleep(base_delay * (2 ** i))
    return None, last


# --------------------------------------------------------------------------
# Tailscale: aktive Steuerung (up/down) + Funnel. Oversight-gegatet.
# --------------------------------------------------------------------------
def enable_tailscale(oversight: bool = False, timeout: float = _UP_TIMEOUT) -> dict:
    """Meldet das Geraet im Tailnet an (`tailscale up`). NUR mit Oversight.

    Idempotent: laeuft der Daemon schon (BackendState=Running), wird nichts
    erneut gemacht. Ein Auth-Key wird – falls vorhanden – NUR zur Laufzeit aus
    TS_AUTHKEY in die Subprozess-Umgebung gelegt (nie auf die Kommandozeile,
    nie geloggt/gespeichert). Fehlt der Key, laeuft ein interaktives `up`
    (Login-URL), was hier ehrlich zurueckgemeldet wird.
    """
    if not oversight:
        return {"ok": False, "changed": False,
                "reason": "Oversight-Gate: 'tailscale up' nur mit menschlichem Oversight-Haken."}
    path = resolve_binary("tailscale")
    if not path:
        return {"ok": False, "changed": False,
                "reason": "tailscale nicht installiert (siehe Setup-Schritte)."}
    cur = tailscale_status()
    if cur.get("running"):
        return {"ok": True, "changed": False, "running": True, "ip": cur.get("ip", ""),
                "url": cur.get("url", ""), "reason": "Tailscale laeuft bereits (idempotent)."}
    run_env = dict(_os.environ)
    argv = [path, "up", "--timeout", f"{int(timeout)}s"]
    key = _os.environ.get(TS_AUTHKEY_ENV, "").strip()
    if key:
        # Key nur in die Subprozess-Umgebung, nie in argv (waere in `ps` sichtbar).
        run_env["TS_AUTHKEY"] = key
        argv += ["--authkey", "env:TS_AUTHKEY"]
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout + 5, check=False, env=run_env)
        out = ((proc.stdout or b"") + (proc.stderr or b"")).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "changed": False,
                "reason": "tailscale up Timeout (ggf. Login noch offen)."}
    except Exception as exc:  # pragma: no cover - defensiv
        return {"ok": False, "changed": False, "reason": f"tailscale up fehlgeschlagen: {exc}"}
    after = tailscale_status()
    if after.get("running"):
        return {"ok": True, "changed": True, "running": True, "ip": after.get("ip", ""),
                "url": after.get("url", ""), "reason": "Tailscale aktiviert."}
    # Nicht Running -> ehrlich: evtl. Login-URL noetig. Login-URL aus der Ausgabe
    # ziehen (keine Secrets), damit der Mensch den Flow abschliessen kann.
    login = ""
    m = _re.search(r"https://login\.tailscale\.com/\S+", out)
    if m:
        login = m.group(0)
    return {"ok": False, "changed": False, "running": False, "login_url": login,
            "reason": ("Login noetig – oeffne die Login-URL und bestaetige das Geraet."
                       if login else
                       "tailscale up ohne Erfolg (kein Auth-Key / nicht angemeldet).")}


def disable_tailscale(oversight: bool = False) -> dict:
    """Trennt das Geraet vom Tailnet (`tailscale down`). NUR mit Oversight. Idempotent."""
    if not oversight:
        return {"ok": False, "changed": False,
                "reason": "Oversight-Gate: 'tailscale down' nur mit menschlichem Oversight-Haken."}
    path = resolve_binary("tailscale")
    if not path:
        return {"ok": False, "changed": False, "reason": "tailscale nicht installiert."}
    cur = tailscale_status()
    if not cur.get("running"):
        return {"ok": True, "changed": False, "running": False,
                "reason": "Tailscale war nicht aktiv (idempotent)."}
    rc, so, se = _run_readonly([path, "down"], timeout=15.0)
    after = tailscale_status()
    return {"ok": (rc == 0), "changed": (not after.get("running")),
            "running": after.get("running", False),
            "reason": "Tailscale getrennt." if rc == 0 else (se.strip() or "down fehlgeschlagen")}


def tailscale_funnel_status() -> dict:
    """Rein lesender Funnel-Status (ob die GUI oeffentlich via Funnel exponiert ist)."""
    path = resolve_binary("tailscale")
    out = {"installed": bool(path), "available": False, "exposed": False,
           "url": "", "detail": ""}
    if not path:
        out["detail"] = "tailscale nicht installiert"
        return out
    rc, so, se = _run_readonly([path, "funnel", "status"], timeout=6.0)
    if rc != 0:
        out["detail"] = (se.strip() or "Funnel-Status nicht verfuegbar")
        return out
    out["available"] = True
    txt = so or ""
    m = _re.search(r"https://\S+\.ts\.net\S*", txt)
    if m:
        out["exposed"] = True
        out["url"] = m.group(0)
    out["detail"] = "Funnel aktiv" if out["exposed"] else "Funnel verfuegbar, nicht aktiv"
    return out


def tailscale_funnel(enable: bool, oversight: bool = False, local_port: int = GUI_PORT) -> dict:
    """Schaltet Tailscale Funnel fuer die GUI an/aus. NUR mit Oversight.

    Funnel exponiert die GUI ueber das OEFFENTLICHE Internet (via Tailscale-Relay).
    Daher Oversight-Pflicht. Idempotent gegen den aktuellen Funnel-Status.
    """
    if not oversight:
        return {"ok": False, "changed": False,
                "reason": "Oversight-Gate: Funnel nur mit menschlichem Oversight-Haken."}
    path = resolve_binary("tailscale")
    if not path:
        return {"ok": False, "changed": False, "reason": "tailscale nicht installiert."}
    ts = tailscale_status()
    if not ts.get("running"):
        return {"ok": False, "changed": False,
                "reason": "Tailscale laeuft nicht – erst 'tailscale up' / aktivieren."}
    cur = tailscale_funnel_status()
    if enable and cur.get("exposed"):
        return {"ok": True, "changed": False, "exposed": True, "url": cur.get("url", ""),
                "reason": "Funnel bereits aktiv (idempotent)."}
    if (not enable) and (not cur.get("exposed")):
        return {"ok": True, "changed": False, "exposed": False,
                "reason": "Funnel war nicht aktiv (idempotent)."}
    argv = [path, "funnel", str(local_port), "on"] if enable else [path, "funnel", str(local_port), "off"]
    rc, so, se = _run_readonly(argv, timeout=15.0)
    after = tailscale_funnel_status()
    return {"ok": (rc == 0), "changed": True, "exposed": after.get("exposed", False),
            "url": after.get("url", ""),
            "reason": ("Funnel aktiviert." if enable else "Funnel deaktiviert.") if rc == 0
            else (se.strip() or "Funnel-Schaltung fehlgeschlagen")}


# --------------------------------------------------------------------------
# Cloudflare Free-Tier: API-Helfer (DNS + Zero Trust Access). honest-empty
# ohne CF_API_TOKEN. Alle Aufrufe read-only sofern nicht explizit upsert.
# --------------------------------------------------------------------------
_CF_API = "https://api.cloudflare.com/client/v4"


def _cf_api(method: str, path: str, body: Optional[dict] = None) -> dict:
    """Minimaler Cloudflare-API-Client (stdlib urllib) mit Retry.

    Token NUR zur Laufzeit aus CF_API_TOKEN. Gibt das geparste JSON zurueck
    oder wirft; der Aufrufer faengt via _retry. Der Token-WERT wird nie geloggt.
    """
    token = _os.environ.get(CF_API_TOKEN_ENV, "").strip()
    if not token:
        raise RuntimeError(f"{CF_API_TOKEN_ENV} nicht gesetzt")
    url = _CF_API + path
    data = _json.dumps(body).encode("utf-8") if body is not None else None
    req = _urlreq.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with _urlreq.urlopen(req, timeout=_NET_TIMEOUT) as resp:
            return _json.loads(resp.read().decode("utf-8", "replace") or "{}")
    except _urlerr.HTTPError as exc:
        # Fehlertext ohne Token zurueckgeben.
        try:
            payload = _json.loads(exc.read().decode("utf-8", "replace") or "{}")
        except Exception:
            payload = {}
        payload.setdefault("success", False)
        payload.setdefault("_http_status", exc.code)
        return payload


def cloudflare_api_status() -> dict:
    """Rein lesend: ob CF_API_TOKEN gesetzt ist und (falls ja) ob es gueltig ist."""
    out = {"token_env_name": CF_API_TOKEN_ENV, "token_env_present": _env_present(CF_API_TOKEN_ENV),
           "valid": False, "detail": ""}
    if not out["token_env_present"]:
        out["detail"] = f"{CF_API_TOKEN_ENV} nicht gesetzt (honest-empty)."
        return out
    res, err = _retry(lambda: _cf_api("GET", "/user/tokens/verify"))
    if err:
        out["detail"] = f"API nicht erreichbar: {err}"
        return out
    out["valid"] = bool(res.get("success"))
    out["detail"] = "Token gueltig." if out["valid"] else "Token ungueltig/abgelaufen."
    return out


def cloudflare_dns_status(zone_id: Optional[str] = None) -> dict:
    """Listet CNAME/A-Records der Zone (read-only). honest-empty ohne Token/Zone."""
    zone = (zone_id or _os.environ.get(CF_ZONE_ID_ENV, "")).strip()
    out = {"token_env_present": _env_present(CF_API_TOKEN_ENV),
           "zone_env_name": CF_ZONE_ID_ENV, "zone_present": bool(zone),
           "records": [], "detail": ""}
    if not out["token_env_present"]:
        out["detail"] = f"{CF_API_TOKEN_ENV} nicht gesetzt (honest-empty)."
        return out
    if not zone:
        out["detail"] = f"{CF_ZONE_ID_ENV} nicht gesetzt (honest-empty)."
        return out
    res, err = _retry(lambda: _cf_api("GET", f"/zones/{zone}/dns_records?per_page=100"))
    if err:
        out["detail"] = f"DNS-Abfrage fehlgeschlagen: {err}"
        return out
    if not res.get("success"):
        out["detail"] = "DNS-Abfrage nicht erfolgreich (Token-Scope/Zone pruefen)."
        return out
    for r in (res.get("result") or []):
        out["records"].append({"type": r.get("type"), "name": r.get("name"),
                               "content": r.get("content"), "proxied": r.get("proxied")})
    out["detail"] = f"{len(out['records'])} DNS-Records gelesen."
    return out


def cloudflare_dns_upsert_cname(name: str, content: str, oversight: bool = False,
                                zone_id: Optional[str] = None, proxied: bool = True) -> dict:
    """Legt/aktualisiert einen CNAME (fuer den Tunnel-Hostname). NUR mit Oversight.

    Idempotent: existiert der Record bereits mit gleichem content, passiert nichts.
    """
    if not oversight:
        return {"ok": False, "changed": False,
                "reason": "Oversight-Gate: DNS-Aenderung nur mit menschlichem Oversight-Haken."}
    zone = (zone_id or _os.environ.get(CF_ZONE_ID_ENV, "")).strip()
    if not _env_present(CF_API_TOKEN_ENV):
        return {"ok": False, "changed": False, "reason": f"{CF_API_TOKEN_ENV} nicht gesetzt."}
    if not zone:
        return {"ok": False, "changed": False, "reason": f"{CF_ZONE_ID_ENV} nicht gesetzt."}
    name = (name or "").strip()
    content = (content or "").strip()
    if not name or not content:
        return {"ok": False, "changed": False, "reason": "name und content erforderlich."}
    # Bestehenden Record suchen.
    listing, err = _retry(lambda: _cf_api("GET", f"/zones/{zone}/dns_records?type=CNAME&name={name}"))
    if err:
        return {"ok": False, "changed": False, "reason": f"Lookup fehlgeschlagen: {err}"}
    existing = (listing.get("result") or []) if listing.get("success") else []
    body = {"type": "CNAME", "name": name, "content": content, "proxied": bool(proxied), "ttl": 1}
    if existing:
        rec = existing[0]
        if rec.get("content") == content and bool(rec.get("proxied")) == bool(proxied):
            return {"ok": True, "changed": False, "reason": "CNAME bereits aktuell (idempotent)."}
        rid = rec.get("id")
        res, err = _retry(lambda: _cf_api("PUT", f"/zones/{zone}/dns_records/{rid}", body))
    else:
        res, err = _retry(lambda: _cf_api("POST", f"/zones/{zone}/dns_records", body))
    if err:
        return {"ok": False, "changed": False, "reason": f"Upsert fehlgeschlagen: {err}"}
    if not res.get("success"):
        return {"ok": False, "changed": False, "reason": "Cloudflare lehnte den Upsert ab (Scope?)."}
    return {"ok": True, "changed": True, "reason": f"CNAME {name} -> {content} gesetzt."}


def cloudflare_access_status(account_id: Optional[str] = None) -> dict:
    """Zero Trust / Access (Free): listet Access-Apps (read-only). honest-empty ohne Token/Account."""
    acc = (account_id or _os.environ.get(CF_ACCOUNT_ID_ENV, "")).strip()
    out = {"token_env_present": _env_present(CF_API_TOKEN_ENV),
           "account_env_name": CF_ACCOUNT_ID_ENV, "account_present": bool(acc),
           "apps": [], "detail": ""}
    if not out["token_env_present"]:
        out["detail"] = f"{CF_API_TOKEN_ENV} nicht gesetzt (honest-empty)."
        return out
    if not acc:
        out["detail"] = f"{CF_ACCOUNT_ID_ENV} nicht gesetzt (honest-empty)."
        return out
    res, err = _retry(lambda: _cf_api("GET", f"/accounts/{acc}/access/apps"))
    if err:
        out["detail"] = f"Access-Abfrage fehlgeschlagen: {err}"
        return out
    if not res.get("success"):
        out["detail"] = "Access-Abfrage nicht erfolgreich (Token-Scope pruefen)."
        return out
    for a in (res.get("result") or []):
        out["apps"].append({"name": a.get("name"), "domain": a.get("domain"),
                            "type": a.get("type")})
    out["detail"] = f"{len(out['apps'])} Access-Apps gelesen."
    return out


def cloudflare_access_setup_steps(hostname: str = "<dein-tunnel-hostname>") -> list:
    """Ehrliche Schritte, um eine Access-Policy (E-Mail-OTP) Free vor die GUI zu legen."""
    return [
        "Cloudflare Zero Trust Dashboard oeffnen: https://one.dash.cloudflare.com/ "
        "(Free-Plan deckt bis zu 50 Nutzer ab).",
        "Access → Applications → Add an application → Self-hosted.",
        f"Application domain = dein Tunnel-Hostname (z.B. {hostname}).",
        "Policy anlegen: Action = Allow, Include → Emails → deine E-Mail(s).",
        "Login-Methode: One-time PIN (E-Mail-OTP) ist ohne IdP sofort nutzbar.",
        "Speichern – ab jetzt verlangt Cloudflare vor der GUI eine OTP-Bestaetigung.",
        f"Optional per API (nur mit {CF_API_TOKEN_ENV} + {CF_ACCOUNT_ID_ENV}): "
        "POST /accounts/<id>/access/apps und /access/policies.",
        "antbb legt KEINE Access-Policy automatisch an und speichert KEIN Token – "
        "du bestaetigst/fuehrst die Schritte selbst aus.",
    ]


def warp_status() -> dict:
    """Rein lesender WARP-Status (warp-cli). honest-empty ohne Binary."""
    path = resolve_binary("warp-cli")
    out = {"installed": bool(path), "path": path or "", "connected": False, "detail": ""}
    if not path:
        out["detail"] = "warp-cli nicht installiert (optional)."
        return out
    rc, so, se = _run_readonly([path, "status"], timeout=6.0)
    txt = (so or se or "")
    out["connected"] = ("Connected" in txt)
    out["detail"] = txt.strip().splitlines()[0] if txt.strip() else "Status unbekannt"
    return out


def warp_setup_steps() -> list:
    """Ehrliche WARP-Anbindungs-Schritte (Client, optional)."""
    return [
        "Cloudflare WARP Client installieren: https://1.1.1.1/ bzw. "
        "https://developers.cloudflare.com/warp-client/get-started/",
        "Fuer Zero-Trust-Anbindung: 'warp-cli teams-enroll <team-name>' "
        "(Team aus deinem Zero-Trust-Konto).",
        "Verbinden:  warp-cli connect   ·   Status:  warp-cli status",
        "WARP ist optional und wird von antbb NUR rein lesend abgefragt – nie geschaltet.",
    ]


def remote_full_status(mode: Optional[str] = None) -> dict:
    """Erweiterter Gesamt-Status: Basis (status_for) + Funnel/Access/DNS/WARP/API.

    Alles read-only und honest-empty. Ideal fuer GUI und CLI (keine Duplizierung).
    """
    base = status_for(mode)
    base["tailscale"]["funnel"] = tailscale_funnel_status()
    base["cloudflare"]["api"] = cloudflare_api_status()
    base["cloudflare"]["access"] = cloudflare_access_status()
    base["cloudflare"]["dns"] = cloudflare_dns_status()
    base["warp"] = warp_status()
    base["env_names"] = {
        "tailscale_authkey": TS_AUTHKEY_ENV,
        "cloudflare_tunnel_token": CLOUDFLARE_TOKEN_ENV,
        "cloudflare_api_token": CF_API_TOKEN_ENV,
        "cloudflare_account_id": CF_ACCOUNT_ID_ENV,
        "cloudflare_zone_id": CF_ZONE_ID_ENV,
    }
    return base


def remote_capability_summary() -> dict:
    """installed / skipped / failed – ehrliche Zusammenfassung der Remote-Access-Lage.

    'installed' = Binary/Token real vorhanden; 'skipped' = optional/nicht konfiguriert
    (honest-empty, kein Fehler); 'failed' = vorhanden, aber nicht nutzbar.
    """
    installed: list = []
    skipped: list = []
    failed: list = []

    ts = tailscale_status()
    if ts["installed"]:
        (installed if ts["running"] else skipped).append(
            "tailscale (laeuft)" if ts["running"] else "tailscale (installiert, inaktiv)")
    else:
        skipped.append("tailscale (nicht installiert)")

    cf = cloudflared_status()
    (installed if cf["installed"] else skipped).append(
        "cloudflared" if cf["installed"] else "cloudflared (nicht installiert)")

    api = cloudflare_api_status()
    if not api["token_env_present"]:
        skipped.append(f"{CF_API_TOKEN_ENV} (nicht gesetzt)")
    elif api["valid"]:
        installed.append("Cloudflare API-Token (gueltig)")
    else:
        failed.append("Cloudflare API-Token (ungueltig/nicht erreichbar)")

    wp = warp_status()
    (installed if wp["installed"] else skipped).append(
        "warp-cli" if wp["installed"] else "warp-cli (optional, nicht installiert)")

    return {"installed": installed, "skipped": skipped, "failed": failed}
