"""Yellow RE-Orchestrator: echte Schritte, echte Artefakte, regelbasierte Next-Steps.

Jeder Schritt läuft nur mit Oversight, schreibt Artefakte in den Case-Ordner
und liefert Funde. next_steps() leitet aus den echten Funden die nächsten
angebotenen Aktionen ab – nichts Statisches.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
import time
import urllib.request
from pathlib import Path

GHIDRA_MCP_URL = "http://127.0.0.1:8089"

_PACKER_SECTIONS = {
    ".aspack": "ASPack", ".adata": "ASPack", ".upx0": "UPX", ".upx1": "UPX",
    ".upx2": "UPX", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".petite": "Petite", ".themida": "Themida", ".enigma1": "Enigma",
    ".enigma2": "Enigma", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
}
_PACKER_MAGICS = [(b"UPX!", "UPX"), (b"MPRESS", "MPRESS")]
_STRINGS_RE = re.compile(rb"[ -~]{5,}")


def case_dir(data_root: Path, case_id: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", case_id)
    d = data_root / "cases" / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_state(d: Path) -> dict:
    f = d / "orchestrator.json"
    if f.is_file():
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except ValueError:
            pass
    return {"steps": {}, "findings": {}, "next_steps": [], "updated_at": None}


def save_state(d: Path, state: dict) -> None:
    state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (d / "orchestrator.json").write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _find_case_file(d: Path) -> Path | None:
    for sub in ("uploads", "sample", ""):
        root = d / sub if sub else d
        if root.is_dir():
            for p in sorted(root.rglob("*")):
                if p.is_file() and p.suffix.lower() in (
                        ".exe", ".dll", ".elf", ".bin", ".apk", ".msi", ".sys", ".scr"):
                    return p
    return None


def _pe_info(data: bytes) -> dict:
    """Minimaler PE-Parser (stdlib): Sections, Imports-Hinweise, EP."""
    info: dict = {"is_pe": False}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return info
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return info
    info["is_pe"] = True
    file_hdr = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, file_hdr + 2)[0]
    opt_size = struct.unpack_from("<H", data, file_hdr + 16)[0]
    ep = struct.unpack_from("<I", data, file_hdr + 20 + 16)[0]
    info["entrypoint_rva"] = hex(ep)
    sec_off = file_hdr + 20 + opt_size
    sections = []
    for i in range(min(nsec, 32)):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append({"name": name, "vaddr": hex(vaddr),
                         "vsize": hex(vsize), "rawptr": hex(rawptr),
                         "rawsize": hex(rawsize)})
    info["sections"] = sections
    info["packer_hints"] = sorted({
        label for s in sections if (label := _PACKER_SECTIONS.get(s["name"].lower()))
    })
    return info


def step_triage(d: Path, sample: Path | None) -> dict:
    if sample is None:
        return {"ok": False, "error": "keine Proben-Datei im Case gefunden"}
    data = sample.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    (d / "triage_hex_head.txt").write_text(_hexdump(data[:512]), encoding="utf-8")
    strings = [m.group().decode("ascii", "replace")
               for m in _STRINGS_RE.finditer(data[:262144])][:200]
    (d / "triage_strings.txt").write_text("\n".join(strings) + "\n", encoding="utf-8")
    pe = _pe_info(data)
    packers = list(pe.get("packer_hints") or [])
    for sig, label in _PACKER_MAGICS:
        if data[:4096].find(sig) >= 0:
            packers.append(label)
    findings = {
        "file": sample.name, "size": len(data), "sha256": digest,
        "is_pe": pe.get("is_pe", False), "entrypoint_rva": pe.get("entrypoint_rva"),
        "sections": pe.get("sections", []), "packer": sorted(set(packers)),
        "strings_count": len(strings),
    }
    (d / "triage_report.json").write_text(
        json.dumps(findings, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "artifacts": ["triage_report.json", "triage_hex_head.txt",
                                      "triage_strings.txt"], "findings": findings}


def step_diec(d: Path, sample: Path | None) -> dict:
    if sample is None:
        return {"ok": False, "error": "keine Proben-Datei im Case gefunden"}
    diec = shutil.which("diec")
    if not diec:
        return {"ok": False, "error": "diec (Detect-It-Easy) nicht installiert"}
    proc = subprocess.run([diec, str(sample)], capture_output=True, text=True, timeout=60)
    out = (proc.stdout or proc.stderr or "").strip()
    (d / "diec.txt").write_text(out + "\n", encoding="utf-8", errors="replace")
    return {"ok": proc.returncode == 0, "artifacts": ["diec.txt"],
            "findings": {"diec": out[:2000]}}


def step_unpack(d: Path, sample: Path | None, findings: dict) -> dict:
    if sample is None:
        return {"ok": False, "error": "keine Proben-Datei"}
    packer = (findings.get("packer") or [])
    if "UPX" not in packer:
        return {"ok": False,
                "error": f"kein unterstützter Packer zum automatischen Entpacken ({packer or 'keiner'}) – manuell im Lab."}
    upx = shutil.which("upx")
    if not upx:
        return {"ok": False, "error": "upx nicht installiert"}
    out = d / (sample.stem + ".unpacked" + sample.suffix)
    proc = subprocess.run([upx, "-d", "-o", str(out), str(sample)],
                          capture_output=True, text=True, timeout=120)
    (d / "unpack.log").write_text(
        (proc.stdout or "") + (proc.stderr or ""), encoding="utf-8", errors="replace")
    if proc.returncode != 0 or not out.is_file():
        return {"ok": False, "error": f"upx rc={proc.returncode}", "artifacts": ["unpack.log"]}
    return {"ok": True, "artifacts": ["unpack.log", out.name],
            "findings": {"unpacked_file": out.name,
                         "unpacked_sha256": hashlib.sha256(out.read_bytes()).hexdigest()}}


def step_ghidra(d: Path, sample: Path | None) -> dict:
    if sample is None:
        return {"ok": False, "error": "keine Proben-Datei"}
    headless = shutil.which("analyzeHeadless") or shutil.which("ghidra-analyzeHeadless")
    if not headless:
        return {"ok": False, "error": "Ghidra (analyzeHeadless) nicht installiert"}
    proj = d / "ghidra_project"
    proj.mkdir(exist_ok=True)
    proc = subprocess.run(
        [headless, str(proj), "case", "-import", str(sample), "-deleteProject"],
        capture_output=True, text=True, timeout=600)
    (d / "ghidra.log").write_text(
        (proc.stdout or "")[-8000:] + (proc.stderr or "")[-4000:],
        encoding="utf-8", errors="replace")
    ok = proc.returncode == 0
    return {"ok": ok, "artifacts": ["ghidra.log"],
            "findings": {"ghidra": "Import+Analyse abgeschlossen" if ok else f"rc={proc.returncode}"}}


def _ghidra_mcp_request(base: str, method: str, path: str,
                        payload: dict | None = None, timeout: int = 30):
    """Ein HTTP-JSON-Request gegen die ghidra-mcp-Brücke. Rueckgabe (body|None, error|None)."""
    url = base.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 - Verbindung/Timeout wird als ehrlicher Fehler gemeldet
        return None, f"{type(e).__name__}: {e}"
    try:
        return json.loads(raw), None
    except ValueError:
        return {"raw": raw}, None


def ghidra_mcp_check(base: str = GHIDRA_MCP_URL, timeout: int = 5) -> dict | None:
    """Liveness der ghidra-mcp Headless-Brücke; None wenn nicht einsatzbereit."""
    body, err = _ghidra_mcp_request(base, "GET", "/check_connection", timeout=timeout)
    if err or not isinstance(body, dict) or body.get("status") != "ok":
        return None
    return body


def _ghidra_mcp_unavailable(reason: str) -> dict:
    return {"ok": False,
            "error": f"ghidra-mcp Headless-Server nicht einsatzbereit ({reason}) "
                     "- Fallback: Schritt 'ghidra' (analyzeHeadless).",
            "fallback": "ghidra", "artifacts": []}


def step_ghidra_mcp(d: Path, sample: Path | None,
                    base: str = GHIDRA_MCP_URL) -> dict:
    """Echte Ghidra-Analyse ueber die MCP/HTTP-Bruecke (127.0.0.1:8089).

    Artefakt: ghidra-functions.json (Funktionen mit Name/Adresse/Xref-Count)
    plus ghidra-mcp.log. Ohne erreichbare Bruecke: ehrliche Note + Fallback 'ghidra'.
    """
    if sample is None:
        return {"ok": False, "error": "keine Proben-Datei"}
    log: list[str] = []
    info = ghidra_mcp_check(base)
    if not info:
        return _ghidra_mcp_unavailable(f"keine Antwort auf {base}/check_connection")
    log.append(f"check_connection: {info}")
    proj = d / "ghidra_project"
    proj.mkdir(exist_ok=True)
    imp, err = _ghidra_mcp_request(base, "POST", "/import_file", timeout=600, payload={
        "file_path": str(sample),
        "project_path": str(proj),
        "project_name": d.name or "case",
    })
    if err or not isinstance(imp, dict) or not imp.get("success"):
        detail = err or (imp or {}).get("error") or str(imp)[:300]
        return _ghidra_mcp_unavailable(f"import_file fehlgeschlagen: {detail}")
    log.append(f"import_file: {imp.get('name')} language={imp.get('language')} "
               f"function_count={imp.get('function_count')}")
    functions: list[dict] = []
    offset, limit, total = 0, 500, None
    while total is None or offset < min(total, 50000):
        body, err = _ghidra_mcp_request(
            base, "GET", f"/find_functions?limit={limit}&offset={offset}", timeout=120)
        if err or not isinstance(body, dict) or not isinstance(body.get("functions"), list):
            return _ghidra_mcp_unavailable(f"find_functions fehlgeschlagen: {err or body}")
        batch = body["functions"]
        total = int(body.get("total") or 0)
        functions.extend({"name": f.get("name"), "address": f.get("address"),
                          "xref_count": f.get("xref_count")} for f in batch)
        offset += len(batch)
        if not batch:
            break
    artifact = {
        "source": "ghidra-mcp", "server": base, "server_kind": info.get("server_kind"),
        "program": imp.get("name"), "language": imp.get("language"),
        "function_count": imp.get("function_count"), "exported": len(functions),
        "total_reported": total, "functions": functions,
    }
    (d / "ghidra-functions.json").write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log.append(f"find_functions: {len(functions)} Funktionen exportiert (total={total})")
    (d / "ghidra-mcp.log").write_text("\n".join(log) + "\n", encoding="utf-8")
    return {"ok": True, "artifacts": ["ghidra-functions.json", "ghidra-mcp.log"],
            "findings": {"ghidra_mcp": True, "ghidra_functions": len(functions),
                         "ghidra_language": imp.get("language")}}


def step_frida(d: Path, sample: Path | None, findings: dict) -> dict:
    note = ("Frida-Hook erfordert die Lab-VM/das Labor-Gerät (dynamic-lab). "
            "Befehlsvorlage liegt bereit – Ausführung nur im Lab mit Oversight.")
    tmpl = ("# frida -U -f <paket> -l hook.js\n"
            "# Ziel: Syscalls/Imports aus den Funden gezielt nachverfolgen\n")
    (d / "frida_hook_plan.txt").write_text(tmpl, encoding="utf-8")
    return {"ok": True, "note": note, "artifacts": ["frida_hook_plan.txt"],
            "findings": {"frida": "Hook-Plan erstellt – Ausführung im Lab"}}


def next_steps(state: dict) -> list[dict]:
    f = state.get("findings") or {}
    steps = state.get("steps") or {}
    out: list[dict] = []
    packed = bool(f.get("packer"))
    unpacked = "unpack" in steps and steps["unpack"].get("ok")
    if "triage" not in steps:
        out.append({"action": "triage", "label": "📋 Triage (Hex/Strings/Sektionen)",
                    "why": "Basisbefund fehlt – Hash, Hex-Dump, PE-Sektionen, Packer-Hinweise."})
        return out
    if packed and not unpacked:
        out.append({"action": "unpack", "label": "📦 Packer-Bypass / Entpacken (Lab)",
                    "why": f"Packer-Hinweise: {', '.join(f['packer'])} – Ghidra auf dem Stub lohnt nicht."})
    static_done = (("ghidra-mcp" in steps and steps["ghidra-mcp"].get("ok"))
                   or ("ghidra" in steps and steps["ghidra"].get("ok")))
    if f.get("is_pe") and not static_done:
        out.append({"action": "ghidra-mcp", "label": "🧠 Ghidra-MCP-Analyse (Headless-Brücke)",
                    "why": "PE vorhanden – Funktionen/Adressen per MCP-API als ghidra-functions.json ins Dossier."})
        if "ghidra" not in steps:
            out.append({"action": "ghidra", "label": "🧠 Ghidra-Headless-Analyse",
                        "why": "Alternative/Fallback zur MCP-Brücke – klassischer analyzeHeadless-Lauf."})
    if "diec" not in steps:
        out.append({"action": "diec", "label": "🔍 Detect-It-Easy",
                    "why": "Packer/Compiler-Identifikation als unabhängiger Beleg."})
    if "frida" not in steps and unpacked:
        out.append({"action": "frida", "label": "🪝 Frida-Hook (Lab)",
                    "why": "Entpackte Probe – dynamische Nachverfolgung der Funde im Lab."})
    if not out:
        out.append({"action": "none", "label": "✅ Abgeschlossen",
                    "why": "Alle sinnvollen Schritte ausgeführt – keine offenen Zweifel mehr."})
    return out


def run_step(data_root: Path, case_id: str, action: str,
             oversight_ok: bool, runner=None) -> dict:
    if not oversight_ok:
        return {"ok": False, "error": "Human-Oversight erforderlich für aktive Analyse."}
    if action not in ("triage", "diec", "unpack", "ghidra", "ghidra-mcp", "frida"):
        return {"ok": False, "error": f"unbekannter Schritt '{action}'"}
    d = case_dir(data_root, case_id)
    state = load_state(d)
    sample = _find_case_file(d)
    findings = state.get("findings") or {}
    run = runner or (lambda fn: fn())
    result = run(lambda: {
        "triage": lambda: step_triage(d, sample),
        "diec": lambda: step_diec(d, sample),
        "unpack": lambda: step_unpack(d, sample, findings),
        "ghidra": lambda: step_ghidra(d, sample),
        "ghidra-mcp": lambda: step_ghidra_mcp(d, sample),
        "frida": lambda: step_frida(d, sample, findings),
    }[action]())
    step_rec = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "ok": bool(result.get("ok")), "result": result}
    state.setdefault("steps", {})[action] = step_rec
    if result.get("ok") and result.get("findings"):
        state.setdefault("findings", {}).update(result["findings"])
    state["next_steps"] = [s for s in next_steps(state) if s["action"] != "none"]
    save_state(d, state)
    return {"ok": bool(result.get("ok")), "step": action, "result": result,
            "state": state}


def _hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<{width * 3}} {ascii_part}")
    return "\n".join(lines) + "\n"
