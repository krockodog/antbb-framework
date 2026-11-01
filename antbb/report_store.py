"""Fester Report-Ablageort je Königin: data/reports/<red|blue|yellow>/.

Erzeugt pro Lauf bzw. Fall einen Report als HTML und (falls PDF-Engine
vorhanden) PDF. Wiederverwendet die bestehende Report-Logik:
  * Red  → brandedreport (gebrandeter Ziel-Report, wie /target/{id}/report.pdf)
  * Blue → Run-Historie (run_history) + Findings des Ziels
  * Yellow → dossier.md / ledger.md des Falls (yellow-queen/queen/reports.py)
PDF-Rendering ausschließlich über brandedreport.render_pdf_bytes (weasyprint
bzw. wkhtmltopdf, honest-empty ohne Engine). Keine Secrets, nur lokale Daten.
Der Ordner data/ ist gitignored – echte Befunde landen nie im Repo.
"""
from __future__ import annotations

import html
import os
import re
import time
from pathlib import Path
from typing import Optional

QUEENS = ("red", "blue", "yellow")
_REPO = Path(__file__).resolve().parent.parent
REPORTS_ROOT = Path(os.environ.get("ANTBB_REPORTS_DIR") or _REPO / "data" / "reports").resolve()
NAME_RE = re.compile(r"^(red|blue|yellow)-[a-z0-9][a-z0-9_-]{0,80}-\d{8}-\d{6}\.(pdf|html)$")
CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,100}$")


class ReportError(ValueError):
    """Ungültige Anfrage (unbekannte Königin, Name, Quelle)."""


def queen_dir(queen: str, root: Optional[Path] = None) -> Path:
    if queen not in QUEENS:
        raise ReportError(f"Unbekannte Königin: {queen!r}")
    d = (Path(root) if root else REPORTS_ROOT) / queen
    d.mkdir(parents=True, exist_ok=True)
    return d


def safe_path(queen: str, name: str, root: Optional[Path] = None) -> Path:
    """Whitelist + resolve(): nur Dateien direkt im Ordner der Königin."""
    if not isinstance(name, str) or not NAME_RE.match(name) or not name.startswith(queen + "-"):
        raise ReportError("Ungültiger Report-Name.")
    base = queen_dir(queen, root).resolve()
    p = (base / name).resolve()
    if p.parent != base:
        raise ReportError("Pfad außerhalb des Report-Ordners.")
    return p


def list_reports(root: Optional[Path] = None) -> dict:
    out = {}
    for q in QUEENS:
        items = []
        d = queen_dir(q, root)
        for p in sorted(d.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if p.is_file() and NAME_RE.match(p.name):
                st = p.stat()
                items.append({"name": p.name, "kind": p.suffix[1:], "size_kb": round(st.st_size / 1024, 1),
                              "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
                              "url": f"/reports/{q}/{p.name}"})
        out[q] = items
    return out


def _slug(s) -> str:
    s = re.sub(r"[^a-z0-9_-]+", "-", str(s).lower()).strip("-")
    return (s or "x")[:60]


def _wrap(title: str, body_html: str, color: str) -> str:
    t = html.escape(title)
    return (f"<!doctype html><html lang='de'><head><meta charset='utf-8'><title>{t}</title>"
            "<style>body{font-family:DejaVu Sans,Arial,sans-serif;font-size:11pt;color:#111;margin:2cm}"
            f"h1{{border-bottom:3px solid {color};padding-bottom:.3em}}table{{border-collapse:collapse;width:100%}}"
            "td,th{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}"
            "pre{white-space:pre-wrap;font-size:9.5pt;background:#f6f6f6;padding:.6em}</style></head>"
            f"<body><h1>{t}</h1>{body_html}<p style='color:#777;font-size:8pt'>Erzeugt "
            f"{time.strftime('%Y-%m-%d %H:%M')} · All and One · nur autorisierte Ziele</p></body></html>")


def _write(queen: str, key: str, doc: str, root: Optional[Path]) -> dict:
    from . import brandedreport as br
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = f"{queen}-{_slug(key)}-{stamp}"
    d = queen_dir(queen, root)
    hp = safe_path(queen, base + ".html", root)
    hp.write_text(doc, encoding="utf-8")
    data, engine, note = br.render_pdf_bytes(doc)
    res = {"ok": True, "queen": queen, "html": f"/reports/{queen}/{hp.name}", "pdf": None,
           "engine": engine, "note": note or "", "dir": str(d)}
    if data:
        pp = safe_path(queen, base + ".pdf", root)
        pp.write_bytes(data)
        res["pdf"] = f"/reports/{queen}/{pp.name}"
    return res


def generate_red(svc, target_id: int, root: Optional[Path] = None) -> dict:
    """Red: gebrandeter Ziel-Report (bestehende brandedreport-Logik)."""
    if not svc.get_target(int(target_id)):
        raise ReportError("Target nicht gefunden.")
    from . import brandedreport as br
    doc = br.build_html(svc.store, int(target_id), br.BrandConfig.from_dict(None))
    return _write("red", f"target{int(target_id)}", doc, root)


def generate_blue(svc, run_key, root: Optional[Path] = None) -> dict:
    """Blue: Lauf aus run_history (Zusammenfassung) + Findings des Ziels."""
    row = None
    for r in svc.store.list_run_history(None):
        d = dict(r)
        if str(d.get("id")) == str(run_key) or str(d.get("run_id")) == str(run_key):
            row = d
            break
    if not row:
        raise ReportError("Lauf nicht gefunden.")
    fields = ["run_id", "target_name", "target_id", "mode", "status", "finding_count",
              "severity", "error", "started_at", "finished_at", "duration"]
    rows = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(str(row.get(k, '')))}</td></tr>" for k in fields)
    body = f"<h2>Lauf</h2><table>{rows}</table>"
    tid = row.get("target_id")
    if tid and svc.get_target(int(tid)):
        from . import brandedreport as br
        body += "<h2>Ziel-Report</h2>" + _strip_body(br.build_html(svc.store, int(tid), br.BrandConfig.from_dict(None)))
    return _write("blue", f"run{_slug(row.get('id'))}", _wrap(f"Blue-Queen-Report · Lauf {row.get('run_id') or row.get('id')}", body, "#3b8bff"), root)


def _strip_body(doc: str) -> str:
    m = re.search(r"<body[^>]*>(.*)</body>", doc, re.S | re.I)
    return m.group(1) if m else doc


def yellow_cases_dir() -> Path:
    env = os.environ.get("YQ_CASES_DIR")
    if env:
        return Path(env).resolve()
    home = os.environ.get("YQ_HOME")
    return (Path(home) if home else _REPO / "yellow-queen").resolve() / "cases"


def generate_yellow(case_id: str, root: Optional[Path] = None, cases_dir: Optional[Path] = None) -> dict:
    """Yellow: dossier.md + ledger.md des Falls (bestehende Fall-Artefakte)."""
    if not CASE_RE.match(str(case_id or "")):
        raise ReportError("Ungültige Fall-ID.")
    base = Path(cases_dir or yellow_cases_dir()).resolve()
    cdir = (base / case_id).resolve()
    if cdir.parent != base or not cdir.is_dir():
        raise ReportError("Fall nicht gefunden.")
    parts = []
    for fn in ("dossier.md", "ledger.md"):
        f = cdir / fn
        if f.is_file():
            parts.append(f"<h2>{fn}</h2><pre>{html.escape(f.read_text(encoding='utf-8', errors='replace'))}</pre>")
    if not parts:
        raise ReportError("Fall hat noch kein Dossier/Ledger.")
    return _write("yellow", case_id, _wrap(f"Yellow-Queen-Report · Fall {case_id}", "".join(parts), "#d4a017"), root)
