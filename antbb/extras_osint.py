"""Extras — passiver OSINT-Katalog fuer die Ameisen (Quelle: enna, nur Daten).

* ``catalog()`` liefert die gefilterten Katalog-Eintraege aus
  ``extras_osint.json`` (erzeugt von tools/import_extras_from_enna.py).
* ``RUNNERS`` definiert fuer eine kleine Teilmenge einen PASSIVEN CLI-Aufruf:
  diese Werkzeuge fragen ausschliesslich Drittquellen (Zertifikats-Logs,
  Archive, Suchindizes) ab und kontaktieren das Ziel selbst nicht.
* ``run_passive()`` fuehrt Runner gegen bereits scope-gepruefte Domains aus
  (die Gates — Scope default-deny, Oversight, mode_policy — liegen beim
  Aufrufer: Hub-Store.start_run bzw. Kolonie-Queen/require_scan_gates).

Es wird nie etwas installiert, kein curl|bash, keine Shell (argv-Listen),
harte Timeouts, Ausgabe gekappt. Fehlt ein Binary: ehrliche Notiz.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path
from typing import Callable, Optional

LABEL = "Extras"
DATA_FILE = Path(__file__).with_name("extras_osint.json")
MAX_TARGETS = 3
MAX_OUTPUT = 512 * 1024
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

# slug -> passiver Aufruf. argv(binary, domain) -> list[str]
RUNNERS: dict[str, dict] = {
    "subfinder": {
        "binary": "subfinder", "timeout": 90,
        "argv": lambda b, d: [b, "-d", d, "-silent", "-timeout", "20", "-max-time", "1"],
        "note": "Passive Subdomain-Quellen (CT-Logs, Archive, APIs).",
    },
    "amass": {
        "binary": "amass", "timeout": 100,
        "argv": lambda b, d: [b, "enum", "-d", d, "-timeout", "1"],
        "note": "amass v5: passiv ist Standard (kein -active, kein -brute).",
    },
    "theharvester": {
        "binary": "theHarvester", "timeout": 90,
        "argv": lambda b, d: [b, "-d", d, "-b", "crtsh,certspotter,hackertarget,rapiddns,otx", "-l", "200"],
        "note": "Nur passive Quellen; kein --dns-brute, kein Screenshot.",
    },
    "waybackurls": {
        "binary": "waybackurls", "timeout": 60, "stdin": True,
        "argv": lambda b, d: [b],
        "note": "Wayback-Machine-Index (archive.org), Ziel wird nicht kontaktiert.",
    },
    "gau": {
        "binary": "gau", "timeout": 90,
        "argv": lambda b, d: [b, "--timeout", "30", "--providers", "wayback,commoncrawl,otx", d],
        "note": "Archive/Indizes (Wayback, CommonCrawl, OTX).",
    },
    "assetfinder": {
        "binary": "assetfinder", "timeout": 60,
        "argv": lambda b, d: [b, "--subs-only", d],
        "note": "Passive Quellen (crt.sh, certspotter, ...).",
    },
    "findomain": {
        "binary": "findomain", "timeout": 90,
        "argv": lambda b, d: [b, "-t", d, "-q"],
        "note": "CT-Logs/APIs, ohne Aufloesung (-q).",
    },
    "sublist3r": {
        "binary": "sublist3r", "timeout": 120,
        "argv": lambda b, d: [b, "-d", d, "-n", "-t", "2"],
        "note": "Suchmaschinen/CT-Quellen; OHNE -b (kein Brute-Force), Ziel wird nicht kontaktiert.",
    },
    "waybackpack": {
        "binary": "waybackpack", "timeout": 60,
        "argv": lambda b, d: [b, d, "--list"],
        "note": "Nur Snapshot-Liste aus dem Wayback-CDX (archive.org), keine Downloads.",
    },
}


@lru_cache(maxsize=1)
def _load() -> dict:
    try:
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"label": LABEL, "tools": []}


def catalog() -> dict:
    """Katalog + Laufzeit-Status (Binary vorhanden / passiv ausfuehrbar)."""
    raw = _load()
    tools = []
    for t in raw.get("tools", []):
        runner = RUNNERS.get(t["slug"])
        present = bool(runner and shutil.which(runner["binary"]))
        tools.append({**t, "runnable": bool(runner), "present": present,
                      "mode": ("passive-cli" if runner else "catalog")})
    return {
        "label": raw.get("label", LABEL), "queen_id": "red", "soldier_id": "extras",
        "source": raw.get("source", ""), "source_total": raw.get("source_total", 0),
        "included_categories": raw.get("included_categories", []),
        "excluded_categories": raw.get("excluded_categories", []),
        "excluded_entries": raw.get("excluded_entries", []),
        "count": len(tools),
        "runnable_count": sum(1 for t in tools if t["runnable"]),
        "present_count": sum(1 for t in tools if t["present"]),
        "tools": tools,
    }


def runnable_slugs() -> list[str]:
    known = {t["slug"] for t in _load().get("tools", [])}
    return [s for s in RUNNERS if s in known]


def clean_domain(value: str) -> str:
    """Nur nackte Domains (kein Schema, keine Flags, keine IPs)."""
    v = (value or "").strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v).split("/")[0].split(":")[0].rstrip(".")
    if v.startswith("*."):
        v = v[2:]
    if not _DOMAIN_RE.match(v) or not re.search(r"[a-z]", v.rsplit(".", 1)[-1]):
        return ""
    return v


def _run_one(slug: str, domain: str, folder: Optional[Path]) -> dict:
    spec = RUNNERS[slug]
    binary = shutil.which(spec["binary"])
    entry = {"tool": slug, "target": domain, "passive": True}
    if not binary:
        entry["note"] = f"{spec['binary']} ist auf diesem Host nicht installiert (keine Auto-Installation)."
        return entry
    argv = spec["argv"](binary, domain)
    started = time.time()
    try:
        proc = subprocess.run(
            argv, input=(domain + "\n") if spec.get("stdin") else None,
            capture_output=True, text=True, timeout=spec["timeout"],
            cwd=str(folder) if folder else None,
        )
        out, err, rc = proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""))
        err, rc = f"Zeitlimit {spec['timeout']}s", -1
        entry["note"] = f"Zeitlimit ({spec['timeout']}s) erreicht — Teilergebnis."
    except OSError as exc:
        entry["note"] = f"nicht ausfuehrbar: {type(exc).__name__}"
        return entry
    out = out[:MAX_OUTPUT]
    lines = sorted({ln.strip() for ln in out.splitlines()
                    if ln.strip() and not ln.startswith(("[", "*", "#"))})
    entry.update({"returncode": rc, "seconds": round(time.time() - started, 1),
                  "result_count": len(lines), "sample": lines[:25]})
    if folder:
        safe = re.sub(r"[^a-z0-9_.-]", "_", f"extras-{slug}-{domain}")
        (folder / f"{safe}.log").write_text(
            f"$ {' '.join(argv)}\n\n=== stdout (rc={rc}) ===\n{out}\n=== stderr ===\n{err[:20000]}\n",
            encoding="utf-8", errors="replace")
        entry["artifact"] = f"{safe}.log"
    return entry


def run_passive(targets: list[str], slugs: Optional[list[str]] = None,
                folder: Optional[Path] = None,
                log: Optional[Callable[[str], None]] = None) -> dict:
    """Passive Extras-Runner gegen bereits scope-gepruefte Ziele.

    Der Aufrufer MUSS Scope (default-deny) + Oversight vorher geprueft haben.
    """
    wanted = [s for s in (slugs or runnable_slugs()) if s in RUNNERS]
    domains, skipped = [], []
    for t in targets:
        d = clean_domain(t)
        (domains if d and d not in domains else skipped).append(d or t)
    domains = domains[:MAX_TARGETS]
    if folder:
        folder.mkdir(parents=True, exist_ok=True)
    jobs = [(s, d) for d in domains for s in wanted]
    if log:
        log(f"Extras (OSINT, passiv): {len(wanted)} Werkzeuge x {len(domains)} Domains")
    results = []
    if jobs:
        with ThreadPoolExecutor(max_workers=min(5, len(jobs))) as pool:
            for res in pool.map(lambda j: _run_one(j[0], j[1], folder), jobs):
                results.append(res)
                if log:
                    log(f"Extras {res['tool']} @ {res['target']}: "
                        f"{res.get('result_count', 0)} Treffer {res.get('note') or ''}".strip())
    payload = {"executor": "extras-osint", "label": LABEL, "stub": False,
               "passive_only": True, "targets": domains, "skipped": skipped,
               "tools": wanted, "results": results,
               "note": (None if domains else "Kein Domain-Ziel im Scope — Extras laufen nur gegen Domains.")}
    if folder:
        (folder / "extras-osint.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload
