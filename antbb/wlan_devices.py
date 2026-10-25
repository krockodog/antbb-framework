"""All-and-One /wlan — Geraete-Erkennung im Heimnetz (nmap, read-only).

Passiv/nicht-destruktiv: nur lokales Subnetz (RFC1918, aus Default-Route),
ARP-/Ping-Sweep plus Versions-Light auf Top-Ports. Kein Intrusives Scannen,
keine Exploits, kein Brute-Force. Oversight-Pflicht.

Liefert pro Geraet: IP, MAC, Hersteller (OUI), Hostname, offene Dienste,
Klassifikation (router/repeater/iot/unknown) sowie Firmware-Hinweise aus
Versionsbannern (regelbasiert, ehrlich als 'moeglich veraltet' markiert).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

# OUI-Hersteller, die typischerweise Router/Repeater/Mesh sind
_OUI_ROUTER = {"avm", "avm gmbh", "fritz"}
_OUI_REPEATER_HINTS = ("avm", "fritz", "tp-link", "netgear", "asus", "devolo", "d-link")
_IOT_OUIS = ("espressif", "tuya", "sonos", "philips", "hue", "shelly", "xiaomi",
             "yeelight", "tp-link", "meross", "govee", "ring", "nest", "amazon")
_IOT_HOST_HINTS = ("esphome", "tasmota", "shelly", "hue", "sonos", "mqtt",
                   "iot", "smart", "plug", "bulb", "camera", "thermo", "sensor")
_IOT_PORTS = {1883, 8883, 554, 5353, 6668, 1400, 8080, 49152, 62078}

# Versionsgrenzen: darunter -> "moeglich veraltet" (ehrlich, ohne garantie)
_OUTDATED_SSH = 7.8          # OpenSSH < 7.8 (2018) gilt als veraltet
_OUTDATED_TLS_HINT = ("ssl2", "ssl3", "tlsv1.0", "tls 1.0", "tlsv1.1", "tls 1.1")


def _have(bin_: str) -> bool:
    return shutil.which(bin_) is not None


def _local_subnet() -> str | None:
    """Ermittelt das lokale IPv4-Subnetz aus der Default-Route (read-only)."""
    try:
        out = subprocess.run(["ip", "-4", "route"], capture_output=True, text=True,
                             timeout=8).stdout
    except Exception:
        return None
    for line in out.splitlines():
        if line.startswith("default"):
            parts = line.split()
            if "via" in parts:
                via = parts[parts.index("via") + 1]
                m = re.match(r"^(\d+\.\d+\.\d+)\.\d+$", via)
                if m:
                    return m.group(1) + ".0/24"
            src = re.search(r"src (\d+\.\d+\.\d+)\.\d+", line)
            if src:
                return src.group(1) + ".0/24"
    return None


def _is_private_subnet(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return net.version == 4 and net.is_private


def classify_device(*, mac: str = "", vendor: str = "", hostname: str = "",
                    ports: list | None = None) -> str:
    """Klassifiziert ein Geraet anhand OUI/Hostname/Ports (ehrlich, heuristisch)."""
    v = (vendor or "").lower()
    h = (hostname or "").lower()
    portset = {int(p) for p in (ports or [])}
    if any(o in v for o in _OUI_ROUTER) and (
            ("fritz" in h and not any(x in h for x in ("repeater", "mesh", "extender")))
            or 49443 in portset or 49000 in portset):
        return "router"
    if ("repeater" in h or "mesh" in h or "extender" in h) and any(o in v for o in _OUI_REPEATER_HINTS):
        return "repeater"
    if any(o in v for o in _OUI_ROUTER) and 80 in portset and not (49443 in portset or 49000 in portset):
        return "repeater" if ("repeater" in h or "mesh" in h) else "router"
    if portset & _IOT_PORTS and (any(o in v for o in _IOT_OUIS) or any(x in h for x in _IOT_HOST_HINTS)):
        return "iot"
    if any(x in h for x in _IOT_HOST_HINTS):
        return "iot"
    if any(o in v for o in _IOT_OUIS) and not portset & {22, 445, 3389}:
        return "iot"
    return "unknown"


def firmware_hints(port_services: list[dict]) -> list[str]:
    """Regelbasierte Firmware-/Versions-Hinweise aus Bannern (keine Garantie)."""
    hints: list[str] = []
    for svc in port_services or []:
        name = (svc.get("service") or "").lower()
        product = (svc.get("product") or "")
        version = str(svc.get("version") or "")
        if name == "ssh" and "openssh" in product.lower() and version:
            try:
                major_minor = float(".".join(version.split(".")[:2]))
                if major_minor < _OUTDATED_SSH:
                    hints.append(f"OpenSSH {version} (möglich veraltet, < {_OUTDATED_SSH})")
            except (TypeError, ValueError):
                pass
        banner = f"{product} {version}".lower()
        if any(t in banner for t in _OUTDATED_TLS_HINT):
            hints.append(f"Altes Protokoll in Banner: {product} {version}".strip())
    return hints


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parst nmap -oX Ausgabe zu einer Geraeteliste (tolerant, ohne nmap-Abhaengigkeit)."""
    devices: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return devices
    for host in root.iter("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = mac = vendor = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        ports: list[dict] = []
        for port in host.findall("ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = port.find("service")
            ports.append({
                "port": int(port.get("portid", "0")),
                "proto": port.get("protocol", "tcp"),
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })
        if not ip:
            continue
        devices.append({
            "ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
            "ports": ports,
            "classification": classify_device(
                mac=mac, vendor=vendor, hostname=hostname,
                ports=[p["port"] for p in ports]),
            "firmware_hints": firmware_hints(ports),
        })
    return devices


def _real_nmap_bin() -> str:
    """Echtes nmap-Binary (ohne den --privileged-Shim) – fuer unprivilegierten
    TCP-Connect-Fallback, wenn sudo im Service-Kontext blockiert ist."""
    return "/usr/lib/nmap/nmap" if os.path.isfile("/usr/lib/nmap/nmap") else "nmap"


def _run_nmap_xml(cmd: list[str], timeout: int = 150) -> tuple[str, bool]:
    """Führt ein nmap-Kommando aus. Reihenfolge: als Root direkt → sudo -n →
    unprivilegiertes echtes Binary (TCP-Connect statt ARP). Rückgabe: (XML, privileged)."""
    base = list(cmd)
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        proc = subprocess.run(base, capture_output=True, text=True, timeout=timeout)
        if "<nmaprun" not in (proc.stdout or ""):
            raise RuntimeError(
                f"nmap rc={proc.returncode}: {(proc.stderr or proc.stdout or '').strip()[:300]}")
        return proc.stdout, True
    if shutil.which("sudo"):
        try:
            proc = subprocess.run(["sudo", "-n"] + base, capture_output=True,
                                  text=True, timeout=timeout)
            if "<nmaprun" in (proc.stdout or ""):
                return proc.stdout, True
        except Exception:
            pass
    # Fallback: ohne Root (kein ARP – Geraete nur per TCP/ICMP erkennbar)
    real = [_real_nmap_bin() if c == "nmap" else c for c in base]
    proc = subprocess.run(real, capture_output=True, text=True, timeout=timeout)
    if "<nmaprun" not in (proc.stdout or ""):
        raise RuntimeError(
            f"nmap rc={proc.returncode}: {(proc.stderr or proc.stdout or '').strip()[:300]}")
    return proc.stdout, False


def _scan_subnet(run, subnet: str, timeout: int = 240) -> tuple[list[dict], bool]:
    """Zwei-Phasen-Scan: (1) ARP-/Ping-Sweep, (2) Dienste nur auf gefundenen
    Hosts (sonst dauert ein /24-Version-Scan zu lange). Rückgabe: (geraete, privileged)."""
    devices: dict[str, dict] = {}
    privileged = True

    def _run(cmds):
        nonlocal privileged
        out = run(cmds, timeout)
        if isinstance(out, tuple):
            xml_text, priv = out
        else:
            xml_text, priv = out, True
        privileged = privileged and bool(priv)
        return xml_text

    xml_hosts = _run(["nmap", "-sn", "--host-timeout", "8s", "-oX", "-", subnet])
    for d in parse_nmap_xml(xml_hosts):
        devices[d["ip"]] = d
    if not devices:
        return [], privileged
    # Phase 2: Versionsbanner nur auf tatsaechlich gefundenen Hosten.
    xml_svc = _run(["nmap", "-F", "--version-light", "--host-timeout", "12s",
                    "-oX", "-"] + sorted(devices))
    for d in parse_nmap_xml(xml_svc):
        cur = devices.get(d["ip"])
        if cur is None:
            devices[d["ip"]] = d
            continue
        cur["ports"] = d["ports"]
        cur["mac"] = cur["mac"] or d["mac"]
        cur["vendor"] = cur["vendor"] or d["vendor"]
        cur["hostname"] = cur["hostname"] or d["hostname"]
        cur["firmware_hints"] = d["firmware_hints"]
        cur["classification"] = classify_device(
            mac=cur["mac"], vendor=cur["vendor"], hostname=cur["hostname"],
            ports=[p["port"] for p in cur["ports"]])
    return list(devices.values()), privileged


def discover_devices(*, runner=None, oversight_ok: bool = False,
                     subnet: str | None = None, timeout: int = 240) -> dict:
    """EIN-KLICK: lokales Subnetz scannen (read-only), Geraete klassifizieren.

    Scope-Regel: nur private lokale Subnetze (RFC1918). Oversight-Pflicht."""
    if not oversight_ok:
        return {"ok": False, "error":
                "Human-Oversight erforderlich (aktiver Netz-Scan)."}
    if not _have("nmap"):
        return {"ok": False, "error":
                "nmap nicht installiert (sudo apt install -y nmap)."}
    cidr = subnet or _local_subnet()
    if not cidr or not _is_private_subnet(cidr):
        return {"ok": False, "error":
                f"Kein lokales privates Subnetz ermittelt ({cidr!r}) – Scan blockiert (Scope-Regel)."}
    run = runner or _run_nmap_xml
    try:
        devices, privileged = _scan_subnet(run, cidr, timeout=timeout)
    except FileNotFoundError:
        return {"ok": False, "error": "nmap nicht gefunden."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "nmap hat das Zeitlimit überschritten."}
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)}
    note = "Read-only Sweep im lokalen Subnetz. Firmware-Hinweise sind Heuristiken, keine Garantie."
    if not privileged:
        note += " Eingeschränkt ohne Root (kein ARP) – Geräte ggf. erst nach Ansprechen eines Dienstes sichtbar."
    return {"ok": True, "subnet": cidr, "devices": devices,
            "count": len(devices), "privileged": privileged, "note": note}


if __name__ == "__main__":
    print(json.dumps(discover_devices(oversight_ok=True), indent=2, ensure_ascii=False))
