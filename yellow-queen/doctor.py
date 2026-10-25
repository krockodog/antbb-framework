"""Tool-Doctor: prüft, welche RE-CLIs vorhanden sind. CLI: python -m yellow_queen.doctor"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

TOOLS = [
    # (id, kandidaten, versions-args, wofür_de)
    ("file", ["file"], ["--version"], "Dateityp (Magic)"),
    ("xxd", ["xxd"], ["-v"], "Hexdump"),
    ("strings", ["strings"], ["--version"], "Strings"),
    ("binwalk", ["binwalk"], ["--help"], "Firmware/Container-Scan"),
    ("diec", ["diec"], ["--version"], "Detect-It-Easy: Packer/Compiler"),
    ("rizin", ["rizin"], ["-v"], "Disassembler/Analyse"),
    ("rz-bin", ["rz-bin", "rabin2"], ["-V"], "Binärinfo (Header/Imports)"),
    ("jadx", ["jadx"], ["--version"], "APK/DEX → Java"),
    ("apktool", ["apktool"], ["--version"], "APK dekodieren (Manifest/smali)"),
    ("ghidra", ["analyzeHeadless", "analyzeHeadless.bat", "ghidraRun"], None, "Decompiler (headless)"),
    ("capa", ["capa"], ["--version"], "Capabilities"),
    ("floss", ["floss"], ["--version"], "Obfuscated Strings"),
    ("objdump", ["objdump"], ["--version"], "Disassembler (binutils)"),
    ("readelf", ["readelf"], ["--version"], "ELF-Header"),
    ("java", ["java"], ["-version"], "Java-Laufzeit (jadx/apktool/ghidra)"),
    ("strace", ["strace"], ["-V"], "Dynamic-Lab: Syscalls (Linux)"),
    ("ltrace", ["ltrace"], ["-V"], "Dynamic-Lab: Library-Calls"),
    ("gdb", ["gdb"], ["--version"], "Dynamic-Lab: Debugger"),
    ("frida", ["frida"], ["--version"], "Dynamic-Lab / Frida-Hooks"),
    ("frida-ps", ["frida-ps"], ["--version"], "Frida Prozessliste"),
]


def find(cands: list[str]) -> str | None:
    extra = os.environ.get("YQ_TOOLS_PATH")
    for c in cands:
        p = shutil.which(c, path=(os.environ.get("PATH", "") + os.pathsep + extra) if extra else None)
        if p:
            return p
    return None


def _version(path: str, args: list[str] | None) -> str:
    if not args:
        return ""
    try:
        r = subprocess.run([path, *args], capture_output=True, text=True, timeout=8, stdin=subprocess.DEVNULL)
        out = (r.stdout or r.stderr or "").strip().splitlines()
        return out[0][:120] if out else ""
    except Exception as e:  # noqa: BLE001
        return f"(Version nicht lesbar: {type(e).__name__})"


def run_doctor(versions: bool = False) -> dict:
    rows = []
    for tid, cands, vargs, why in TOOLS:
        rows.append({"id": tid, "path": find(cands), "version": "", "why_de": why, "_v": vargs})
    if versions:
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {r["id"]: ex.submit(_version, r["path"], r["_v"]) for r in rows if r["path"]}
            for r in rows:
                if r["id"] in futs:
                    r["version"] = futs[r["id"]].result()
    for r in rows:
        r.pop("_v")
        r["present"] = bool(r["path"])
    present = sum(r["present"] for r in rows)
    return {
        "queen_id": "yellow",
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "present": present,
        "total": len(rows),
        "tools": rows,
        "hinweis_de": "Fehlende Tools sind kein Fehler: Soldaten nutzen dann eingebaute Python-Fallbacks (Header-Parser, Strings, Hexdump).",
    }


def main() -> int:
    d = run_doctor(versions=True)
    print(f"Yellow Queen – Tool-Doctor  (Python {d['python']}, {d['platform']})")
    for r in d["tools"]:
        mark = "OK " if r["present"] else "-- "
        print(f" [{mark}] {r['id']:<8} {r['path'] or 'fehlt':<40} {r['version']}")
    print(f"{d['present']}/{d['total']} Tools gefunden. {d['hinweis_de']}")
    if "--json" in sys.argv:
        print(json.dumps(d, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
