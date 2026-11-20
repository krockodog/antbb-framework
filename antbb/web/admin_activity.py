"""/admin/activity: Live-Uebersicht + ISMS-Aenderungslog (nur admin).

Quellen:
* activity_events / session_meta / sessions (antbb-DB, siehe activity.py)
* changes.jsonl + agent-status.json aus ANTBB_HARDENING_LOG_DIR
  (Default /opt/antbb/hardening-log, read-only gemountet vom Host
  /home/ubuntu/antbb-hardening-log). Nur lesen, nie schreiben.
Exporte: CSV und druckfertiges ISMS-PDF (isms_report.render_pdf_bytes).
"""
from __future__ import annotations

import html
import json
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from .. import webauth
from . import activity

MAX_LINES = 5000


def _dir() -> Path:
    return Path(os.environ.get("ANTBB_HARDENING_LOG_DIR", "/opt/antbb/hardening-log"))


def _require_admin(request: Request) -> dict:
    user = getattr(request.state, "user", None) or {}
    if not webauth.is_admin(user.get("role")):
        raise HTTPException(403, "Only an admin may run this action.")
    return user


def read_changes() -> tuple[list[dict], str]:
    p = _dir() / "changes.jsonl"
    if not p.is_file():
        return [], "changes.jsonl nicht gefunden (Mount fehlt?)."
    rows, bad = [], 0
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        rows.append(obj)
                except ValueError:
                    bad += 1
    except OSError as exc:
        return [], f"changes.jsonl nicht lesbar ({type(exc).__name__})."
    rows = rows[-MAX_LINES:]
    rows.sort(key=lambda r: str(r.get("ts", "")), reverse=True)
    return rows, (f"{bad} ungültige Zeile(n) übersprungen." if bad else "")


def read_status() -> tuple[list[dict], str]:
    p = _dir() / "agent-status.json"
    if not p.is_file():
        return [], "agent-status.json nicht gefunden."
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return ([d for d in data if isinstance(d, dict)] if isinstance(data, list) else []), ""
    except (OSError, ValueError) as exc:
        return [], f"agent-status.json nicht lesbar ({type(exc).__name__})."


def _filter(rows: list[dict], category: str, stream: str, result: str) -> list[dict]:
    def ok(r):
        return ((not category or str(r.get("category", "")) == category)
                and (not stream or str(r.get("stream", "")) == stream)
                and (not result or str(r.get("result", "")) == result))
    return [r for r in rows if ok(r)]


def _fmt(ts) -> str:
    if ts in (None, ""):
        return "–"
    try:
        return time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(float(ts)))
    except (TypeError, ValueError):
        return str(ts)


def live(store) -> dict:
    return {
        "now": time.time(),
        "sessions": activity.active_sessions(store),
        "logins": activity.events(store, kinds=activity.LOGIN_KINDS
                                  + ("login_password_ok_2fa_pending", "invite_accepted"), limit=100),
        "admin": activity.events(store, exclude=activity.LOGIN_KINDS, limit=150),
        "agents": read_status()[0],
        "retention_days": activity.retention_days(),
    }


FIELDS = ["ts", "actor", "stream", "category", "action", "detail", "reason", "backup_ref",
          "rollback", "result", "iso_control", "severity", "risk_before", "risk_after"]


def _csv(rows: list[dict]) -> bytes:
    from ..isms_report import export_csv
    flat = []
    for r in rows:
        d = {}
        for k in FIELDS:
            v = r.get(k, "")
            d[k] = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
        flat.append(d)
    return export_csv(flat, FIELDS)


def _risk_txt(v) -> str:
    if isinstance(v, dict):
        return f"W{v.get('W', v.get('likelihood', '?'))}×A{v.get('A', v.get('impact', '?'))}={v.get('score', '?')} ({v.get('band', v.get('stufe', ''))})"
    return str(v or "")


def report_html(changes: list[dict], live_data: dict, *, title: str = "ISMS-Änderungsprotokoll") -> str:
    e = html.escape
    ts_all = sorted(str(r.get("ts", "")) for r in changes if r.get("ts"))
    period = f"{ts_all[0]} – {ts_all[-1]}" if ts_all else "–"
    per_cat = Counter(str(r.get("category", "–")) for r in changes)
    per_res = Counter(str(r.get("result", "–")) for r in changes)
    controls = Counter()
    for r in changes:
        for c in (r.get("iso_control") or "").replace(";", ",").split(",") if isinstance(r.get("iso_control"), str) else (r.get("iso_control") or []):
            c = str(c).strip()
            if c:
                controls[c] += 1
    now = datetime.now(timezone.utc).astimezone().strftime("%d.%m.%Y %H:%M %Z")
    rows = "".join(
        "<tr>" + "".join(f"<td>{e(str(x))}</td>" for x in (
            r.get("ts", ""), r.get("actor", ""), r.get("stream", ""), r.get("category", ""),
            r.get("action", ""), r.get("detail", ""), r.get("iso_control", "") if not isinstance(r.get("iso_control"), list) else ", ".join(r["iso_control"]),
            _risk_txt(r.get("risk_before")), _risk_txt(r.get("risk_after")),
            r.get("result", ""), r.get("backup_ref", ""), r.get("rollback", ""))) + "</tr>"
        for r in changes)
    cat_rows = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in per_cat.most_common())
    ctl_rows = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in sorted(controls.items()))
    ses = "".join(f"<tr><td>{e(s['username'] or '')}</td><td>{e(s['role'] or '')}</td><td>{_fmt(s['since'])}</td>"
                  f"<td>{_fmt(s['last_seen'])}</td><td>{e(s['ip'] or '')}</td><td>{e(s['ua'] or '')}</td></tr>"
                  for s in live_data.get("sessions", []))
    logins = "".join(f"<tr><td>{_fmt(x['ts'])}</td><td>{e(x['kind'])}</td><td>{e(x.get('username') or '')}</td>"
                     f"<td>{e(x.get('ip') or '')}</td></tr>" for x in live_data.get("logins", [])[:60])
    return f"""<!doctype html><html lang="de"><head><meta charset="utf-8"><title>{e(title)}</title>
<style>@page{{size:A4 landscape;margin:12mm}}body{{font:9pt/1.35 DejaVu Sans,sans-serif;color:#111}}
h1{{font-size:15pt;margin:0 0 4mm}}h2{{font-size:11pt;margin:6mm 0 2mm}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #999;padding:1.5mm;vertical-align:top;text-align:left}}th{{background:#eee}}
.kopf td{{border:0;padding:.5mm 2mm}}</style></head><body>
<h1>{e(title)}</h1>
<table class="kopf"><tr><td><b>Organisation:</b></td><td>&nbsp;</td></tr>
<tr><td><b>System:</b></td><td>antbb.carescribe.online / ntfy.carescribe.online</td></tr>
<tr><td><b>Zeitraum:</b></td><td>{e(period)}</td></tr>
<tr><td><b>Erstellt:</b></td><td>{e(now)}</td></tr>
<tr><td><b>Einträge:</b></td><td>{len(changes)} · Ergebnis: {e(', '.join(f'{k}={v}' for k, v in per_res.items()))}</td></tr></table>
<h2>Zusammenfassung pro Kategorie</h2><table><tr><th>Kategorie</th><th>Anzahl</th></tr>{cat_rows or '<tr><td colspan=2>–</td></tr>'}</table>
<h2>Annex-A-Bezug (ISO/IEC 27001:2022)</h2><table><tr><th>Control</th><th>Einträge</th></tr>{ctl_rows or '<tr><td colspan=2>–</td></tr>'}</table>
<h2>Änderungen</h2><table><tr><th>Zeit</th><th>Akteur</th><th>Strang</th><th>Kategorie</th><th>Aktion</th><th>Detail</th><th>Annex A</th><th>Risiko vorher</th><th>Risiko nachher</th><th>Ergebnis</th><th>Backup</th><th>Rückweg</th></tr>{rows or '<tr><td colspan=12>–</td></tr>'}</table>
<h2>Aktive Sitzungen (Stand Export)</h2><table><tr><th>Benutzer</th><th>Rolle</th><th>seit</th><th>zuletzt aktiv</th><th>IP</th><th>Client</th></tr>{ses or '<tr><td colspan=6>–</td></tr>'}</table>
<h2>Anmelde-Historie (neueste 60)</h2><table><tr><th>Zeit</th><th>Ereignis</th><th>Benutzer</th><th>IP</th></tr>{logins or '<tr><td colspan=4>–</td></tr>'}</table>
<p style="margin-top:5mm;color:#555">Aufbewahrung Aktivitäts-Log: {live_data.get('retention_days')} Tage (Hinweis; es wird derzeit nichts gelöscht). Passwörter werden nie protokolliert; Einladungs-Tokens sind maskiert.</p>
</body></html>"""


def register(app: FastAPI, templates, store_getter: Callable[[], Any]) -> None:
    @app.get("/admin/activity", response_class=HTMLResponse, include_in_schema=False)
    def admin_activity(request: Request, category: str = "", stream: str = "", result: str = ""):
        _require_admin(request)
        rows, note = read_changes()
        cats = sorted({str(r.get("category", "")) for r in rows if r.get("category")})
        streams = sorted({str(r.get("stream", "")) for r in rows if r.get("stream")})
        results = sorted({str(r.get("result", "")) for r in rows if r.get("result")})
        shown = _filter(rows, category, stream, result)
        return templates.TemplateResponse(request, "admin_activity.html", {
            "rows": shown[:500], "total": len(rows), "note": note,
            "cats": cats, "streams": streams, "results": results,
            "f": {"category": category, "stream": stream, "result": result},
            "live": live(store_getter()), "fmt_ts": _fmt, "risk_txt": _risk_txt,
        })

    @app.get("/api/admin/activity/live", include_in_schema=False)
    def api_activity_live(request: Request):
        _require_admin(request)
        data = live(store_getter())
        for key in ("logins", "admin"):
            for x in data[key]:
                x["ts_h"] = _fmt(x.get("ts"))
        for s in data["sessions"]:
            s["since_h"], s["last_seen_h"] = _fmt(s.get("since")), _fmt(s.get("last_seen"))
        return data

    @app.get("/admin/activity/export.csv", include_in_schema=False)
    def admin_activity_csv(request: Request, category: str = "", stream: str = "", result: str = ""):
        _require_admin(request)
        rows, _ = read_changes()
        activity.record(store_getter(), request, "isms_export", detail="csv")
        return Response(_csv(_filter(rows, category, stream, result)), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="isms-aenderungen.csv"'})

    @app.get("/admin/activity/report.pdf", include_in_schema=False)
    def admin_activity_pdf(request: Request, category: str = "", stream: str = "", result: str = ""):
        _require_admin(request)
        from ..isms_report import render_pdf_bytes
        rows, _ = read_changes()
        doc = report_html(_filter(rows, category, stream, result), live(store_getter()))
        activity.record(store_getter(), request, "isms_export", detail="pdf")
        pdf, engine, note = render_pdf_bytes(doc)
        if pdf:
            return Response(pdf, media_type="application/pdf",
                            headers={"Content-Disposition": 'attachment; filename="isms-aenderungen.pdf"'})
        return HTMLResponse(doc, headers={"X-AntBB-PDF-Engine": engine or "missing"})
