"""
All-and-One /wlan — Client-Enumeration (Stations) via Monitor-Mode.
Gate-pflichtig (Human-Oversight), scope-gebunden, nicht-destruktiv:
NUR passives Mithören (airodump-ng). KEIN Deauth/Injection.

Ablauf (automatisch, mit Aufräumen):
  1. Interface in Monitor-Mode (airmon-ng ODER iw/ip fallback)
  2. airodump-ng kurz laufen lassen, CSV auswerten -> APs + Stations(Clients)
  3. Monitor-Mode zuruecknehmen (managed), NetworkManager wieder frei

Erfordert Root (sudo). Ohne Root/Monitor-Fähigkeit: ehrliche Fehlermeldung.
Scope: nur BSSIDs/SSIDs aus der autorisierten Allowlist zurückgeben (default-deny).
"""
from __future__ import annotations
import csv, glob, os, re, shutil, subprocess, tempfile, time
from dataclasses import dataclass, field

@dataclass
class Station:
    mac: str
    power: int | None
    packets: int
    assoc_bssid: str      # "(not associated)" oder BSSID
    probes: list[str] = field(default_factory=list)

@dataclass
class AccessPoint:
    bssid: str
    channel: str
    power: int | None
    essid: str
    privacy: str

def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

def _have(bin_): return shutil.which(bin_) is not None

def _is_root(): return os.geteuid() == 0

# ---------- Monitor-Mode an/aus ----------
def enable_monitor(iface: str) -> tuple[str, str]:
    """Rückgabe: (monitor_iface, methode). Wirft RuntimeError bei Fehlschlag."""
    # NetworkManager den Adapter freigeben (falls vorhanden)
    if _have("nmcli"):
        _run(["nmcli", "dev", "set", iface, "managed", "no"])
    if _have("airmon-ng"):
        _run(["airmon-ng", "check", "kill"])          # stoert sonst
        r = _run(["airmon-ng", "start", iface])
        # airmon nennt es oft <iface>mon oder wlan1mon / monX
        m = re.search(r"(monitor mode (?:vif )?enabled.*?\]?\s*)?(\w+mon|\bmon\d+)\b", r.stdout)
        cand = (m.group(2) if m else None)
        for guess in filter(None, [cand, iface + "mon", iface]):
            if _iface_is_monitor(guess):
                return guess, "airmon-ng"
    # Fallback via iw/ip
    _run(["ip", "link", "set", iface, "down"])
    r = _run(["iw", "dev", iface, "set", "type", "monitor"])
    _run(["ip", "link", "set", iface, "up"])
    if _iface_is_monitor(iface):
        return iface, "iw"
    raise RuntimeError(f"Monitor-Mode fehlgeschlagen fuer {iface}: {r.stderr.strip()}")

def _iface_is_monitor(iface: str) -> bool:
    r = _run(["iw", "dev", iface, "info"])
    return "type monitor" in r.stdout

def disable_monitor(mon_iface: str, orig_iface: str):
    if _have("airmon-ng"):
        _run(["airmon-ng", "stop", mon_iface])
    _run(["ip", "link", "set", mon_iface, "down"])
    _run(["iw", "dev", mon_iface, "set", "type", "managed"])
    _run(["ip", "link", "set", orig_iface, "up"])
    if _have("nmcli"):
        _run(["nmcli", "dev", "set", orig_iface, "managed", "yes"])
        _run(["systemctl", "restart", "NetworkManager"])

# ---------- airodump-ng CSV parsen ----------
def _parse_airodump_csv(path: str):
    aps: list[AccessPoint] = []; stations: list[Station] = []
    with open(path, newline="", errors="replace") as f:
        text = f.read()
    if "Station MAC" not in text:
        return aps, stations
    ap_block, st_block = text.split("Station MAC", 1)
    # APs
    for row in csv.reader(ap_block.splitlines()):
        if len(row) >= 14 and re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", row[0].strip(), re.I):
            aps.append(AccessPoint(row[0].strip(), row[3].strip(),
                                   _int(row[8]), row[13].strip(), row[5].strip()))
    # Stations
    st_lines = ("Station MAC" + st_block).splitlines()[1:]
    for row in csv.reader(st_lines):
        if len(row) >= 6 and re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", row[0].strip(), re.I):
            probes = [p.strip() for p in row[6:] if p.strip()] if len(row) > 6 else []
            stations.append(Station(row[0].strip(), _int(row[3]),
                                    _int(row[4]) or 0, row[5].strip(), probes))
    return aps, stations

def _int(s):
    try: return int(str(s).strip())
    except Exception: return None

# ---------- Hauptfunktion ----------
def enumerate_clients(iface: str = "wlan1", seconds: int = 20,
                      channel: str | None = None,
                      allowlist_bssids: set[str] | None = None,
                      oversight_ok: bool = False) -> dict:
    if not oversight_ok:
        return {"ok": False, "error": "Human-Oversight erforderlich (Monitor-Mode ist eine aktive Aktion)."}
    if not _is_root():
        return {"ok": False, "error": "Root/sudo erforderlich fuer Monitor-Mode (airmon-ng/iw)."}
    if not _have("airodump-ng"):
        return {"ok": False, "error": "airodump-ng nicht installiert (aircrack-ng Paket)."}
    mon = None
    try:
        mon, method = enable_monitor(iface)
        tmp = tempfile.mkdtemp(prefix="airodump_")
        prefix = os.path.join(tmp, "scan")
        cmd = ["airodump-ng", "--write", prefix, "--output-format", "csv",
               "--write-interval", "1"]
        if channel: cmd += ["--channel", str(channel)]
        cmd += [mon]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(max(5, seconds)); proc.terminate()
        try: proc.wait(timeout=5)
        except Exception: proc.kill()
        csvs = sorted(glob.glob(prefix + "*.csv"))
        aps, stations = ([], [])
        if csvs:
            aps, stations = _parse_airodump_csv(csvs[-1])
        # Scope-Filter (default-deny): nur Stations zu erlaubten BSSIDs + unassoziierte
        if allowlist_bssids:
            al = {b.upper() for b in allowlist_bssids}
            aps = [a for a in aps if a.bssid.upper() in al]
            stations = [s for s in stations
                        if s.assoc_bssid.upper() in al or "not associated" in s.assoc_bssid.lower()]
        return {"ok": True, "method": method, "monitor_iface": mon,
                "aps": [a.__dict__ for a in aps],
                "clients": [s.__dict__ for s in stations],
                "count": len(stations),
                "note": "Passives Mithören, kein Deauth/Injection. Scope default-deny."}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        if mon:
            try: disable_monitor(mon, iface)
            except Exception: pass

if __name__ == "__main__":
    import json
    print(json.dumps(enumerate_clients(oversight_ok=True), indent=2, ensure_ascii=False))
