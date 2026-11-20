"""ISMS- und Königinnen-Berichte nach ISO/IEC 27001:2022.

Daten stammen ausschließlich aus Store, Blue-Ledger und Yellow-Fällen.
Fehlende Angaben werden als „keine Daten“ oder „[AUSZUFÜLLEN]“ markiert.
Es werden keine Funde erfunden. Secrets aus Evidence werden gefiltert.
"""
from __future__ import annotations

import csv
import html
import io
import json
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Iterable, Optional

from . import brandedreport as br
from . import findingreport as fr
from . import iso27001 as iso
from . import proofgate as pg
from .agents.base import AgentFinding

DISCLAIMER = (
    "Vorlage zur Auditvorbereitung nach ISO/IEC 27001:2022. "
    "Dieses Dokument ersetzt keine Zertifizierung, keine formale "
    "Managementbewertung und keine unabhängige Auditaussage."
)
PLACEHOLDER = "[AUSZUFÜLLEN]"
NO_DATA = "keine Daten"
BERLIN = timezone(timedelta(hours=1), name="Europe/Berlin")

ORG_FIELDS = [
    ("org_name", "Organisationsname"),
    ("legal_entity", "Rechtsträger"),
    ("isms_scope", "ISMS-Geltungsbereich (Kap. 4)"),
    ("context_internal", "Interne Themen (Kap. 4.1)"),
    ("context_external", "Externe Themen (Kap. 4.1)"),
    ("interested_parties", "Interessierte Parteien (Kap. 4.2)"),
    ("policy_title", "Titel der ISMS-Leitlinie (5.2)"),
    ("policy_approved_by", "Leitlinie freigegeben durch"),
    ("policy_approved_on", "Freigabedatum der Leitlinie"),
    ("policy_text", "Wortlaut / Kernaussagen der Leitlinie"),
    ("isms_manager", "ISMS-Verantwortliche/r"),
    ("risk_owner_default", "Standard-Risikoeigentümer"),
    ("roles_text", "Rollen und Verantwortlichkeiten"),
    ("acceptance_threshold", "Akzeptanzschwelle (Risikoscore, Default 15)"),
    ("review_chair", "Vorsitz Managementbewertung (9.3)"),
    ("audit_programme", "Internes Auditprogramm (9.2)"),
]


def _now_label() -> str:
    return datetime.now(BERLIN).strftime("%d.%m.%Y %H:%M") + " Europe/Berlin"


def _esc(s: Any) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def _g(row: Any, key: str, default: str = "") -> Any:
    return fr._g(row, key, default)


def load_org(store) -> dict:
    raw = store.get_setting("isms_org", "") if store is not None else ""
    data = {}
    if raw:
        try:
            data = json.loads(raw) or {}
        except Exception:
            data = {}
    out = {k: (str(data.get(k) or "").strip()) for k, _ in ORG_FIELDS}
    # acceptance threshold: keep default unless a positive int was provided
    try:
        th = int(out.get("acceptance_threshold") or iso.DEFAULT_ACCEPTANCE_THRESHOLD)
    except ValueError:
        th = iso.DEFAULT_ACCEPTANCE_THRESHOLD
    out["acceptance_threshold"] = str(th)
    out["_threshold_is_default"] = "acceptance_threshold" not in data or not str(
        data.get("acceptance_threshold") or ""
    ).strip()
    return out


def save_org(store, updates: dict) -> dict:
    cur = load_org(store)
    for k, _ in ORG_FIELDS:
        if k in updates and updates[k] is not None:
            cur[k] = str(updates[k]).strip()
    # do not persist helper keys
    cur.pop("_threshold_is_default", None)
    store.set_setting("isms_org", json.dumps(cur, ensure_ascii=False))
    return load_org(store)


def org_value(org: dict, key: str) -> str:
    v = (org or {}).get(key) or ""
    return v if v.strip() else PLACEHOLDER


def _fmt_ts(ts) -> str:
    """Format a unix timestamp or ISO string in Europe/Berlin. Honest empty otherwise."""
    if ts in (None, "", 0, "0"):
        return ""
    try:
        if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.replace(".", "", 1).isdigit()):
            dt = datetime.fromtimestamp(float(ts), BERLIN)
            return dt.strftime("%d.%m.%Y %H:%M") + " Europe/Berlin"
    except Exception:
        pass
    s = str(ts).strip()
    # already a label or ISO
    if "Europe/Berlin" in s:
        return s
    try:
        raw = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=BERLIN)
        return dt.astimezone(BERLIN).strftime("%d.%m.%Y %H:%M") + " Europe/Berlin"
    except Exception:
        return s


_SELFTEST_MARKERS = (
    "carescribe.online",
    "127.0.0.1:1001",
    "localhost:1001",
    "antbb-selftest",
)


def is_selftest(item: dict) -> bool:
    blob = " ".join(str(item.get(k) or "") for k in
                    ("asset", "title", "description", "target_name", "filename", "id", "run_id"))
    return any(m in blob.lower() or m in blob for m in _SELFTEST_MARKERS)


def _proof_label(item: dict, *, implemented: bool = False) -> str:
    queen = (item.get("queen") or "").upper() or "APP"
    title = (item.get("title") or item.get("id") or "").strip() or NO_DATA
    run = item.get("run_id") or item.get("id") or ""
    when = item.get("when") or _fmt_ts(item.get("created_at") or item.get("last_seen"))
    bits = [queen, title]
    if implemented:
        bits.append("umgesetzt")
    if run:
        bits.append(f"Run {run}")
    if when:
        bits.append(when)
    if is_selftest(item):
        bits.append("Testlauf (eigenes System)")
    started_by = str(item.get("started_by") or "")
    if started_by == "Gast" or "gestartet von Gast" in started_by:
        bits.append("gestartet von Gast")
    return " · ".join(bits)


def _row_to_af(row) -> AgentFinding:
    return AgentFinding(
        agent=_g(row, "agent", ""),
        title=_g(row, "title", ""),
        category=_g(row, "category", ""),
        severity=_g(row, "severity", "info"),
        asset=_g(row, "asset", ""),
        description=_g(row, "description", ""),
        evidence=fr.parse_evidence(row),
        status=_g(row, "status", ""),
        false_positive=bool(_g(row, "false_positive", 0)),
    )


def _is_blue_finding(agent: str = "", category: str = "", run_id: str = "") -> bool:
    """Blue-Queen observations live in the same findings table as Red."""
    a = (agent or "").lower()
    c = (category or "").lower()
    r = str(run_id or "").lower()
    return a.startswith("blue") or c.startswith("blue-") or r.startswith("blue-")


def _blue_check_status(title: str = "", category: str = "", status: str = "") -> str:
    """Map a stored Blue observation to pass / fail / info. Never invent a result."""
    st = (status or "").strip().lower()
    if st in ("pass", "fail"):
        return st
    t = title or ""
    c = (category or "").lower()
    if t.startswith("[FAIL]") or c.endswith("-gap") or c.endswith("-fail"):
        return "fail"
    if t.startswith("[PASS]") or c.endswith("-pass"):
        return "pass"
    return "info"


def _started_by_map(store) -> dict[str, str]:
    out: dict[str, str] = {}
    if store is None:
        return out
    try:
        for row in store.list_run_history(limit=500):
            rid = str(row["run_id"] if "run_id" in row.keys() else "")
            who = ""
            try:
                who = str(row["started_by"] if "started_by" in row.keys() else "")
            except Exception:
                who = ""
            if rid and who:
                out[rid] = who
    except Exception:
        return out
    return out


def collect_red(store, target_id: Optional[int] = None) -> list[dict]:
    """Pentest findings already stored by the app. Nothing is invented."""
    if store is None:
        return []
    rows = store.list_findings(target_id)
    by_map = _started_by_map(store)
    afs = [_row_to_af(r) for r in rows]
    pg.enforce(afs, None)
    out = []
    for r, af in zip(rows, afs):
        if af.false_positive:
            continue
        if _is_blue_finding(af.agent, af.category, _g(r, "run_id", "")):
            continue
        chain = fr.chain_from_finding(store, r)
        ev_pairs = br._evidence_appendix(r)
        L, I, li_note = iso.severity_to_li(af.severity)
        score = iso.risk_score(L, I)
        controls = iso.map_controls(af.category, af.agent, af.title, af.description)
        tgt_name = ""
        try:
            tgt = store.get_target(int(_g(r, "target_id", 0) or 0))
            if tgt:
                tgt_name = _g(tgt, "name", "")
        except Exception:
            tgt_name = ""
        when = _fmt_ts(_g(r, "created_at", ""))
        out.append({
            "queen": "red",
            "id": _g(r, "id", ""),
            "target_id": _g(r, "target_id", ""),
            "target_name": tgt_name,
            "run_id": _g(r, "run_id", ""),
            "started_by": by_map.get(str(_g(r, "run_id", "")), ""),
            "when": when,
            "created_at": _g(r, "created_at", ""),
            "agent": af.agent,
            "title": af.title or "(ohne Titel)",
            "category": af.category,
            "severity": af.severity,
            "asset": af.asset,
            "description": af.description,
            "status": af.status,
            "cvss_score": chain.get("cvss_score"),
            "cvss_vector": chain.get("cvss_vector") or "",
            "cvss_note": chain.get("cvss_note") or "",
            "recommendation": fr.remediation_for(r),
            "evidence": ev_pairs,
            "likelihood": L,
            "impact": I,
            "li_note": li_note,
            "score": score,
            "band": iso.risk_band(score, int(load_org(store)["acceptance_threshold"])),
            "controls": controls,
        })
    return out


def _blue_item_from_ledger(cid: str, rec: dict) -> dict:
    status = rec.get("status") or NO_DATA
    title = rec.get("title") or cid
    sev = rec.get("severity") or ("high" if status == "fail" else "info")
    detail = rec.get("detail") or rec.get("last_detail") or ""
    L, I, li_note = iso.severity_to_li(sev if status == "fail" else "info")
    score = iso.risk_score(L, I)
    last = rec.get("last_seen") or rec.get("closed_at") or rec.get("failed_since") or rec.get("first_seen")
    when = _fmt_ts(last)
    rec_run = rec.get("run_id") or rec.get("last_run_id") or ""
    return {
        "queen": "blue",
        "id": cid,
        "title": title,
        "status": status,
        "severity": sev if status == "fail" else "info",
        "asset": rec.get("asset") or "eigener Server (Blue-Ledger)",
        "description": detail,
        "recommendation": rec.get("recommendation") or rec.get("fix") or "",
        "evidence": [("status", status), ("detail", str(detail)[:400])] if detail or status else [],
        "likelihood": L,
        "impact": I,
        "li_note": li_note,
        "score": score,
        "band": iso.risk_band(score),
        "controls": iso.map_controls("hardening", "blue", title, str(detail)),
        "cvss_score": None,
        "cvss_vector": "",
        "cvss_note": "",
        "agent": "blue",
        "category": "hardening",
        "run_id": rec_run,
        "target_id": rec.get("target_id") or "",
        "target_name": rec.get("target_name") or "",
        "when": when,
        "created_at": last,
        "last_seen": last,
    }


def _blue_item_from_finding(store, r, af) -> dict:
    status = _blue_check_status(af.title, af.category, af.status)
    sev = af.severity if status == "fail" else "info"
    L, I, li_note = iso.severity_to_li(sev)
    score = iso.risk_score(L, I)
    tgt_name = ""
    try:
        tgt = store.get_target(int(_g(r, "target_id", 0) or 0))
        if tgt:
            tgt_name = _g(tgt, "name", "")
    except Exception:
        tgt_name = ""
    when = _fmt_ts(_g(r, "created_at", ""))
    return {
        "queen": "blue",
        "id": _g(r, "id", ""),
        "title": af.title or "(ohne Titel)",
        "status": status,
        "severity": sev,
        "asset": af.asset or tgt_name or "eigener Server (Blue-Fund)",
        "description": af.description,
        "recommendation": fr.remediation_for(r),
        "evidence": br._evidence_appendix(r),
        "likelihood": L,
        "impact": I,
        "li_note": li_note,
        "score": score,
        "band": iso.risk_band(score),
        "controls": iso.map_controls(af.category, af.agent, af.title, af.description),
        "cvss_score": None,
        "cvss_vector": "",
        "cvss_note": "",
        "agent": af.agent,
        "category": af.category,
        "run_id": _g(r, "run_id", ""),
        "target_id": _g(r, "target_id", ""),
        "target_name": tgt_name,
        "when": when,
        "created_at": _g(r, "created_at", ""),
        "last_seen": _g(r, "created_at", ""),
    }


def collect_blue(store=None, target_id: Optional[int] = None) -> list[dict]:
    """Blue checks from the ledger and/or stored Blue findings. Nothing is invented."""
    items: list[dict] = []
    seen: set[str] = set()

    if store is not None:
        try:
            rows = store.list_findings(target_id)
        except Exception:
            rows = []
        for r in rows:
            af = _row_to_af(r)
            if af.false_positive:
                continue
            if not _is_blue_finding(af.agent, af.category, _g(r, "run_id", "")):
                continue
            item = _blue_item_from_finding(store, r, af)
            items.append(item)
            key = (item.get("title") or "").strip().lower()
            if key:
                seen.add(key)

    try:
        from . import blue_checks as bc
        led = bc.ledger_load() or {}
    except Exception:
        led = {}
    checks = led.get("checks") or {}
    for cid, rec in checks.items():
        if not isinstance(rec, dict):
            continue
        item = _blue_item_from_ledger(cid, rec)
        key = (item.get("title") or "").strip().lower()
        if key and key in seen:
            continue
        items.append(item)
        if key:
            seen.add(key)
    return items


def collect_yellow() -> list[dict]:
    """Yellow RE cases if the yellow-queen DB is reachable. Honest empty otherwise."""
    try:
        from yellow_queen import db as ydb  # type: ignore
        cases = ydb.list_cases(200)
    except Exception:
        try:
            import sys
            root = os.environ.get("YELLOW_QUEEN_ROOT") or os.environ.get("ANTBB_COLONY_ROOT") or ""
            if root and root not in sys.path:
                sys.path.insert(0, root)
            from yellow_queen import db as ydb  # type: ignore
            cases = ydb.list_cases(200)
        except Exception:
            return []
    items = []
    for c in cases or []:
        title = c.get("filename") or c.get("id") or "(ohne Dateiname)"
        desc = " · ".join(
            str(x) for x in [
                f"Art: {c.get('kind') or NO_DATA}",
                f"Route: {c.get('route') or NO_DATA}",
                f"Status: {c.get('status') or NO_DATA}",
                f"SHA-256: {c.get('sha256') or NO_DATA}",
                f"Größe: {c.get('size') or NO_DATA}",
            ]
        )
        when = _fmt_ts(c.get("created_at"))
        items.append({
            "queen": "yellow",
            "id": c.get("id") or "",
            "title": f"RE-Fall: {title}",
            "status": c.get("status") or NO_DATA,
            "severity": "info",
            "asset": c.get("filename") or "",
            "description": desc,
            "recommendation": "RE-Dossier und Oversight-Protokoll im Fallordner prüfen.",
            "evidence": [(k, str(c.get(k) or NO_DATA)) for k in
                         ("id", "kind", "route", "status", "sha256", "packed", "dynamic", "created_at")],
            "likelihood": 1,
            "impact": 1,
            "li_note": "RE-Fall ohne bewertete Vulnerability-Severity — L/I nicht abgeleitet, Score nur informativ.",
            "score": 1,
            "band": "sehr niedrig",
            "controls": iso.map_controls("re", "yellow", title, desc),
            "cvss_score": None,
            "cvss_vector": "",
            "cvss_note": "kein CVSS (RE-Fall, keine bewertete Schwachstelle)",
            "agent": "yellow",
            "category": "re",
            "run_id": c.get("id") or "",
            "target_id": "",
            "target_name": "",
            "when": when,
            "created_at": c.get("created_at"),
            "filename": c.get("filename") or "",
        })
    return items



def _select_proofs(labels: list[str], limit: int = 8) -> list[str]:
    """Keep at least one proof per Queen so a Yellow case is not squeezed out."""
    if not labels:
        return []
    picked: list[str] = []
    seen_q: set[str] = set()
    rest: list[str] = []
    for lab in labels:
        q = (lab.split(" · ", 1)[0] or "").strip().upper()
        if q in {"RED", "BLUE", "YELLOW"} and q not in seen_q:
            picked.append(lab)
            seen_q.add(q)
        else:
            rest.append(lab)
    for lab in rest:
        if len(picked) >= limit:
            break
        picked.append(lab)
    picked = picked[:limit]
    leftover = len(labels) - len(picked)
    if leftover > 0:
        picked.append(f"+{leftover} weitere")
    return picked


def risk_register(items: Iterable[dict], org: Optional[dict] = None) -> list[dict]:
    org = org or {}
    owner = org.get("risk_owner_default") or PLACEHOLDER
    th = int(org.get("acceptance_threshold") or iso.DEFAULT_ACCEPTANCE_THRESHOLD)
    rows = []
    for it in items:
        band = iso.risk_band(it["score"], th)
        rows.append({
            **it,
            "band": band,
            "owner": owner,
            "threat": it.get("category") or it.get("agent") or NO_DATA,
            "vulnerability": it.get("title") or NO_DATA,
            "treatment": iso.default_treatment(band),
            "residual": iso.residual_default(band, treated=False),
            "color": iso.risk_color(it["score"]),
        })
    rows.sort(key=lambda r: (-int(r["score"]), str(r.get("title") or "")))
    return rows


QUEEN_ORDER = ("red", "blue", "yellow")
QUEEN_LABEL = {
    "red": "Red Queen — Pentest",
    "blue": "Blue Queen — Härtung und Abwehr",
    "yellow": "Yellow Queen — Reverse Engineering",
}


def _queen_of(item: dict) -> str:
    q = str(item.get("queen") or "").strip().lower()
    return q if q in QUEEN_ORDER else "app"


def group_by_queen(items: Iterable[dict]) -> dict[str, list[dict]]:
    """Strict Red/Blue/Yellow separation; order inside a group is kept."""
    out: dict[str, list[dict]] = {q: [] for q in QUEEN_ORDER}
    for it in items or []:
        out.setdefault(_queen_of(it), []).append(it)
    return out


def _limit_labels(labels: list[str], limit: int) -> list[str]:
    picked = list(labels[:limit])
    leftover = len(labels) - len(picked)
    if leftover > 0:
        picked.append(f"+{leftover} weitere")
    return picked


def build_soa(register: list[dict], org: Optional[dict] = None,
              blue_items: Optional[list[dict]] = None) -> list[dict]:
    """Statement of Applicability for all 93 Annex A controls.

    Gaps come from the risk register (Red findings, failed Blue checks,
    Yellow cases). Passed Blue checks are recorded as 'umgesetzt' evidence
    with run id and date. Nothing is invented. Evidence is kept strictly
    separated per Queen (Red only with Red, Blue only with Blue, Yellow only
    with Yellow) in ``evidence_parts``; ``evidence`` is the flat CSV form.
    """
    ids = [c["id"] for c in iso.annex_a_controls()]
    # gaps[cid][queen] -> labels ; done[cid] -> labels (Blue only)
    gaps: dict[str, dict[str, list[str]]] = {cid: {} for cid in ids}
    done: dict[str, list[str]] = {cid: [] for cid in ids}
    for r in register:
        label = _proof_label(r)
        q = _queen_of(r)
        for cid in r.get("controls") or []:
            gaps.setdefault(cid, {}).setdefault(q, []).append(label)
    for b in blue_items or []:
        if (b.get("status") or "") != "pass":
            continue
        label = _proof_label(b, implemented=True)
        for cid in b.get("controls") or []:
            done.setdefault(cid, []).append(label)
    rows = []
    for c in iso.annex_a_controls():
        g = gaps.get(c["id"]) or {}
        ok = done.get(c["id"]) or []
        parts: list[dict] = []
        for q in QUEEN_ORDER + ("app",):
            if g.get(q):
                parts.append({"queen": q, "kind": "Lücke", "labels": _limit_labels(g[q], 3)})
            if q == "blue" and ok:
                parts.append({"queen": "blue", "kind": "umgesetzt", "labels": _limit_labels(ok, 3)})
        has_gap = any(p["kind"] == "Lücke" for p in parts)
        if has_gap and ok:
            status = "teilweise (Lücke und umgesetzt dokumentiert)"
            applicable = "ja"
            justification = "Zugeordnet anhand dokumentierter Funde und bestandener Blue-Prüfungen."
        elif ok:
            status = "umgesetzt"
            applicable = "ja"
            justification = "Bestandene Blue-Prüfung als Nachweis (Run-ID und Datum)."
        elif has_gap:
            status = "Lücke / Hinweis durch Funde nachgewiesen"
            applicable = "ja"
            justification = "Zugeordnet anhand der dokumentierten Fund-Kategorie (Methoden-Mapping)."
        else:
            status = NO_DATA
            # Short form; the long Default-explanation is a footnote above the table.
            applicable = "ja (Default)"
            justification = PLACEHOLDER
        if parts:
            proof = " | ".join(
                f"{p['queen'].upper()} – {'Lücken' if p['kind'] == 'Lücke' else 'Umgesetzt'}: "
                + "; ".join(p["labels"]) for p in parts
            )
        else:
            proof = NO_DATA
        rows.append({
            "id": c["id"],
            "title": c["title"],
            "theme": c["theme"],
            "applicable": applicable,
            "justification": justification,
            "status": status,
            "evidence": proof,
            "evidence_parts": parts,
        })
    return rows


def _targets_summary(store) -> list[dict]:
    if store is None:
        return []
    try:
        out = []
        for t in store.list_targets():
            d = dict(t) if not isinstance(t, dict) else dict(t)
            try:
                d["scopes"] = [dict(s) for s in store.list_scopes(d.get("id"))]
            except Exception:
                d["scopes"] = []
            d["scope_count"] = len(d["scopes"])
            out.append(d)
        return out
    except Exception:
        return []


def collect_bundle(store, target_id: Optional[int] = None) -> dict:
    org = load_org(store)
    red = collect_red(store, target_id)
    blue = collect_blue(store, target_id)
    yellow = collect_yellow()
    reg = risk_register(red + [b for b in blue if b.get("status") == "fail"] + yellow, org)
    soa = build_soa(reg, org, blue_items=blue)
    targets = _targets_summary(store)
    return {
        "org": org,
        "generated_at": _now_label(),
        "disclaimer": DISCLAIMER,
        "red": red,
        "blue": blue,
        "yellow": yellow,
        "register": reg,
        "soa": soa,
        "targets": targets,
        "counts": {
            "red": len(red),
            "blue": len(blue),
            "blue_fail": sum(1 for b in blue if b.get("status") == "fail"),
            "yellow": len(yellow),
            "register": len(reg),
            "soa": len(soa),
            "targets": len(targets),
        },
    }


# ---------------------------------------------------------------------------
# HTML (WeasyPrint)
# ---------------------------------------------------------------------------

_CSS = """
/* Einheitliche Ränder Hoch/Quer; Tabellen nutzen die volle Satzspiegelbreite. */
@page {
  size: A4 portrait;
  margin: 16mm 14mm 18mm 14mm;
  @top-center { content: "ISO/IEC 27001:2022 ISMS-Vorlage"; font-size: 8pt; color: #555; }
  @bottom-center { content: "Seite " counter(page) " von " counter(pages); font-size: 8pt; color: #555; }
}
@page landscape {
  size: A4 landscape;
  margin: 16mm 14mm 18mm 14mm;
  @top-center { content: "ISO/IEC 27001:2022 ISMS-Vorlage — breite Tabellen (Register / Behandlungsplan / SoA)"; font-size: 8pt; color: #555; }
  @bottom-center { content: "Seite " counter(page) " von " counter(pages); font-size: 8pt; color: #555; }
}
html, body { font-family: "DejaVu Sans", "Liberation Sans", sans-serif; font-size: 10pt; color: #1a1a1a; }
body { margin: 0; padding: 0; }
h1 { font-size: 20pt; margin: 0 0 6pt; color: #1B3A4B; }
h2 { font-size: 14pt; margin: 22pt 0 10pt; color: #1B3A4B; border-bottom: 2px solid #1B3A4B; padding-bottom: 3pt;
     break-after: avoid; page-break-after: avoid; }
h3 { font-size: 12pt; margin: 16pt 0 8pt; color: #245; break-after: avoid; page-break-after: avoid; }
h2 + p, h3 + p, p.lead, p.footnote { break-after: avoid; page-break-after: avoid; }
p, li { line-height: 1.4; orphans: 3; widows: 3; }
p { margin: 0 0 8pt; }
ul { margin: 4pt 0 10pt; }
.cover { text-align: center; padding: 36mm 8mm 16mm; }
.cover .eyebrow { letter-spacing: .12em; text-transform: uppercase; color: #5a6; font-size: 9pt; }
.disclaimer { background: #FFF6D6; border: 1px solid #C9A227; padding: 8pt 10pt; margin: 12pt 0; font-size: 9pt; }
.placeholder { background: #F4F1EA; color: #6A5A00; padding: 0 3pt; }
.nodata { color: #666; font-style: italic; }
/* Tabellen: jede Zeile bleibt zusammen (kein Eintrag/keine Nummer wird über
   Seiten zerrissen), Kopf wird je Seite wiederholt, und ein wiederholter
   Tabellenfuß schließt die Tabelle auf JEDER Seite mit einer Linie ab. */
table { border-collapse: collapse; width: 100%; max-width: 100%; margin: 10pt 0 18pt; font-size: 8.5pt;
        table-layout: fixed; box-sizing: border-box; border: 1px solid #8A99A3; }
th, td { border: 1px solid #A9B6BE; padding: 4pt 5pt; vertical-align: top; overflow-wrap: anywhere;
         word-wrap: break-word; hyphens: auto; }
th { background: #1B3A4B; color: #fff; font-weight: 600; text-align: left; }
tr { break-inside: avoid; page-break-inside: avoid; }
tbody tr:nth-child(even) td { background: #F7F9FA; }
thead { display: table-header-group; }
tfoot { display: table-footer-group; }
tfoot td.tclose { border: 0; border-top: 1.5pt solid #1B3A4B; padding: 0; height: 0; font-size: 0; line-height: 0;
                  background: transparent !important; }
td.num { font-weight: 600; overflow-wrap: anywhere; word-break: break-all; }
.matrix { border-collapse: collapse; margin: 10pt auto 16pt; table-layout: fixed; width: auto; border: 0; }
.matrix th, .matrix td { width: 22mm; height: 14mm; text-align: center; border: 1px solid #fff; color: #111; font-weight: 600; overflow-wrap: normal; }
.matrix th { text-align: center; }
.badge { display: inline-block; padding: 1pt 6pt; border-radius: 3pt; color: #fff; font-size: 8pt; }
.meta { color: #555; font-size: 9pt; }
.keep { break-inside: avoid; page-break-inside: avoid; }
.footnote { font-size: 8.5pt; color: #333; margin: 0 0 8pt; }
.page-landscape { page: landscape; }
.page-portrait { break-before: page; page: auto; }
.new-sheet { break-before: page; page-break-before: always; }
.queen-head { padding: 3pt 7pt; border-left: 5pt solid #999; background: #F2F4F5; }
.queen-red { border-left-color: #B3261E; }
.queen-blue { border-left-color: #1E5AA8; }
.queen-yellow { border-left-color: #C9A227; }
.qtag { display: inline-block; font-weight: 700; font-size: 7.5pt; padding: 0 3pt; border-radius: 2pt; color: #fff; }
.qtag-red { background: #B3261E; } .qtag-blue { background: #1E5AA8; } .qtag-yellow { background: #8A6D00; }
.qtag-app { background: #555; }
.evq { margin: 0 0 3pt; }
.evq:last-child { margin-bottom: 0; }
table.wide { font-size: 8pt; }
table.soa col.c-id { width: 7%; }
table.soa col.c-title { width: 17%; }
table.soa col.c-theme { width: 10%; }
table.soa col.c-appl { width: 8%; }
table.soa col.c-just { width: 14%; }
table.soa col.c-stat { width: 12%; }
table.soa col.c-ev { width: 32%; }
table.register col.c-id { width: 6%; }
table.register col.c-asset { width: 12%; }
table.register col.c-threat { width: 9%; }
table.register col.c-vuln { width: 16%; }
table.register col.c-li { width: 16%; }
table.register col.c-owner { width: 8%; }
table.register col.c-treat { width: 11%; }
table.register col.c-res { width: 10%; }
table.register col.c-ann { width: 12%; }
table.treat col.c-id { width: 7%; } table.treat col.c-risk { width: 20%; } table.treat col.c-src { width: 7%; }
table.treat col.c-treat { width: 13%; } table.treat col.c-rec { width: 33%; } table.treat col.c-owner { width: 11%; }
table.treat col.c-due { width: 9%; }
table.measures col.c-id { width: 9%; } table.measures col.c-rec { width: 37%; } table.measures col.c-src { width: 18%; }
table.measures col.c-owner { width: 12%; } table.measures col.c-treat { width: 12%; } table.measures col.c-due { width: 12%; }
table.findings col.c-id { width: 6%; } table.findings col.c-title { width: 19%; } table.findings col.c-cvss { width: 15%; }
table.findings col.c-ev { width: 24%; } table.findings col.c-rec { width: 27%; } table.findings col.c-ann { width: 9%; }
table.findings.nocvss col.c-cvss { width: 10%; } table.findings.nocvss col.c-title { width: 22%; }
table.findings.nocvss col.c-ev { width: 25%; } table.findings.nocvss col.c-rec { width: 28%; }
table.raci col.c-act { width: 25%; }
table.audit col.c-n { width: 6%; } table.audit col.c-q { width: 54%; } table.audit col.c-r { width: 40%; }
"""


def _ph(text: str) -> str:
    t = text or PLACEHOLDER
    cls = "placeholder" if t == PLACEHOLDER else ("nodata" if t == NO_DATA else "")
    return f'<span class="{cls}">{_esc(t)}</span>' if cls else _esc(t)


def _matrix_html(threshold: int) -> str:
    head = "<tr><th>L \\ I</th>" + "".join(
        f"<th>{n}<br><small>{iso.IMPACT_LABELS[n]}</small></th>" for n in range(1, 6)
    ) + "</tr>"
    body = []
    for L in range(5, 0, -1):
        cells = [f"<th>{L}<br><small>{iso.LIKELIHOOD_LABELS[L]}</small></th>"]
        for I in range(1, 6):
            s = L * I
            cells.append(
                f'<td style="background:{iso.risk_color(s)};color:#fff">{s}'
                f'<br><small>{iso.risk_band(s, threshold)}</small></td>'
            )
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f'<table class="matrix">{head}{"".join(body)}</table>'


def _close_tables(doc: str) -> str:
    """Add a repeated <tfoot> closing line to every data table.

    WeasyPrint repeats table-footer-group on every page fragment, so each
    page that a table spans ends with a solid closing rule (no open tables
    at the page end). The colspan is taken from the header row.
    """
    import re

    def _fix(m: "re.Match[str]") -> str:
        head = m.group(0)
        if "<tfoot" in head:
            return head
        n = len(re.findall(r"<th[\s>]", head.split("<thead>", 1)[1].split("</tr>", 1)[0]))
        n = max(n, 1)
        return head + f'<tfoot><tr><td class="tclose" colspan="{n}"></td></tr></tfoot>'

    return re.sub(r"<table(?![^>]*class=\"matrix\")[^>]*>.*?</thead>", _fix, doc, flags=re.S)


def _qtag(q: str) -> str:
    q = (q or "app").lower()
    return f'<span class="qtag qtag-{_esc(q)}">{_esc(q.upper())}</span>'


def _queen_heading(num: str, q: str, title: str, *, new_sheet: bool) -> str:
    cls = f"queen-head queen-{q}" + (" new-sheet" if new_sheet else "")
    label = QUEEN_LABEL.get(q, q.upper())
    return f'<h3 class="{cls}">{_esc(num)} {_esc(label)} — {_esc(title)}</h3>'


def _per_queen(items: list[dict], num: str, title: str, render, empty_msg: str,
               *, first_new_sheet: bool = False, queens: Optional[tuple] = None) -> str:
    """Render one sub-section per Queen; each later Queen starts on a new sheet."""
    groups = group_by_queen(items)
    out = []
    order = list(queens or QUEEN_ORDER)
    if groups.get("app") and queens is None:
        order.append("app")
    for i, q in enumerate(order):
        rows = groups.get(q) or []
        out.append(_queen_heading(f"{num}.{i + 1}", q, title, new_sheet=(i > 0 or first_new_sheet)))
        if rows:
            out.append(render(rows))
        else:
            out.append(f'<p class="nodata">{NO_DATA} — {_esc(empty_msg)} ({_esc(q.upper())}).</p>')
    return "".join(out)


# Judith (10.11.2026): Fund-ID 31 im Red-Nachweisanhang beginnt immer auf
# einem neuen Blatt (Weißraum davor ist gewollt).
RED_FORCE_NEW_SHEET_IDS = {"31"}


def _findings_table(items: list[dict], with_cvss: bool = True,
                    force_new_sheet_ids: Optional[set] = None) -> str:
    if not items:
        return f'<p class="nodata">{NO_DATA} — es liegen keine dokumentierten Einträge vor.</p>'
    rows = []
    for it in items:
        cvss = ""
        if with_cvss:
            score = it.get("cvss_score")
            vec = it.get("cvss_vector") or ""
            note = it.get("cvss_note") or ""
            if score:
                cvss = f"{score}" + (f" ({_esc(vec)})" if vec else "")
                if note:
                    cvss += f"<br><small>{_esc(note)}</small>"
            else:
                cvss = _ph(NO_DATA if not note else note)
        ev = it.get("evidence") or []
        ev_html = "<br>".join(f"<strong>{_esc(k)}:</strong> {_esc(v)}" for k, v in ev[:6]) or _ph(NO_DATA)
        ctrls = ", ".join(it.get("controls") or []) or _ph(NO_DATA)
        rec = it.get("recommendation") or NO_DATA
        tr = ("<tr class='new-sheet'>" if force_new_sheet_ids
              and str(it.get("id")) in force_new_sheet_ids else "<tr>")
        rows.append(
            tr +
            f"<td class='num'>{_esc(it.get('id'))}</td>"
            f"<td>{_esc(it.get('title'))}<br><small>{_esc(it.get('asset') or '')} · "
            f"{_esc(it.get('status') or '')} · {_esc(it.get('severity') or '')}</small></td>"
            f"<td>{cvss or _ph(NO_DATA)}</td>"
            f"<td>{ev_html}</td>"
            f"<td>{_esc(rec)}</td>"
            f"<td>{_esc(ctrls)}</td>"
            "</tr>"
        )
    cls = "findings" if with_cvss else "findings nocvss"
    return (
        f"<table class='{cls}'><colgroup><col class='c-id'><col class='c-title'><col class='c-cvss'>"
        "<col class='c-ev'><col class='c-rec'><col class='c-ann'></colgroup>"
        "<thead><tr><th>ID</th><th>Fund</th><th>CVSS</th>"
        "<th>Nachweis</th><th>Empfehlung</th><th>Annex A</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )



def _register_table(reg: list[dict]) -> str:
    if not reg:
        return f'<p class="nodata">{NO_DATA} — das Risikoregister enthält keine Einträge aus App-Läufen.</p>'
    rows = []
    for r in reg:
        testhint = "Testlauf (eigenes System)" if is_selftest(r) else ""
        rows.append(
            "<tr>"
            f"<td class='num'>{_esc(r.get('id'))}</td>"
            f"<td>{_esc(r.get('asset') or NO_DATA)}"
            f"{'<br><small>'+_esc(testhint)+'</small>' if testhint else ''}</td>"
            f"<td>{_esc(r.get('threat'))}</td>"
            f"<td>{_esc(r.get('vulnerability'))}</td>"
            f"<td>{r.get('likelihood')} × {r.get('impact')} = "
            f"<span class='badge' style='background:{r.get('color')}'>{r.get('score')} {r.get('band')}</span>"
            f"<br><small>{_esc(r.get('li_note'))}</small></td>"
            f"<td>{_ph(r.get('owner'))}</td>"
            f"<td>{_esc(r.get('treatment'))}</td>"
            f"<td>{_ph(r.get('residual'))}</td>"
            f"<td>{_esc(', '.join(r.get('controls') or [])) or _ph(NO_DATA)}</td>"
            "</tr>"
        )
    return (
        '<table class="wide register"><colgroup>'
        '<col class="c-id"><col class="c-asset"><col class="c-threat"><col class="c-vuln">'
        '<col class="c-li"><col class="c-owner"><col class="c-treat"><col class="c-res"><col class="c-ann">'
        "</colgroup><thead><tr><th>ID</th><th>Asset</th><th>Bedrohung</th>"
        "<th>Schwachstelle</th><th>L × I</th><th>Eigentümer</th>"
        "<th>Behandlung (6.1.3)</th><th>Restrisiko</th><th>Annex A</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _soa_evidence_html(r: dict) -> str:
    parts = r.get("evidence_parts")
    if not parts:
        return _ph(r.get("evidence") or NO_DATA)
    out = []
    for p in parts:
        q = p.get("queen") or "app"
        pref = q.upper() + " · "
        labs = [lab[len(pref):] if lab.startswith(pref) else lab for lab in p.get("labels") or []]
        out.append(
            f'<div class="evq">{_qtag(q)} <strong>{_esc(p.get("kind"))}:</strong> '
            + "; ".join(_esc(x) for x in labs) + "</div>"
        )
    return "".join(out)


def _soa_table(soa: list[dict]) -> str:
    rows = []
    for r in soa:
        rows.append(
            "<tr>"
            f"<td class='num'>{_esc(r['id'])}</td><td>{_esc(r['title'])}</td>"
            f"<td>{_esc(r['theme'])}</td><td>{_ph(r['applicable'])}</td>"
            f"<td>{_ph(r['justification'])}</td><td>{_ph(r['status'])}</td>"
            f"<td>{_soa_evidence_html(r)}</td>"
            "</tr>"
        )
    return (
        '<table class="wide soa"><colgroup>'
        '<col class="c-id"><col class="c-title"><col class="c-theme"><col class="c-appl">'
        '<col class="c-just"><col class="c-stat"><col class="c-ev">'
        "</colgroup><thead><tr><th>Control</th><th>Titel</th><th>Thema</th>"
        "<th>Anwendbar</th><th>Begründung</th><th>Umsetzung</th><th>Nachweis</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _treatment_plan_table(reg: list[dict]) -> str:
    if not reg:
        return f'<p class="nodata">{NO_DATA}.</p>'
    rows = []
    for r in reg:
        rec = r.get("recommendation") or PLACEHOLDER
        testhint = "Testlauf (eigenes System)" if is_selftest(r) else ""
        rows.append(
            "<tr>"
            f"<td class='num'>{_esc(r.get('id'))}</td>"
            f"<td>{_esc(r.get('title'))}"
            f"{'<br><small>'+_esc(testhint)+'</small>' if testhint else ''}</td>"
            f"<td>{_esc((r.get('queen') or '').upper())}</td>"
            f"<td>{_esc(r.get('treatment'))}</td>"
            f"<td>{_ph(rec) if rec == PLACEHOLDER else _esc(rec)}</td>"
            f"<td>{_ph(r.get('owner'))}</td>"
            f"<td>{_ph(PLACEHOLDER)}</td>"
            "</tr>"
        )
    return (
        "<table class='wide treat'><colgroup><col class='c-id'><col class='c-risk'><col class='c-src'>"
        "<col class='c-treat'><col class='c-rec'><col class='c-owner'><col class='c-due'></colgroup>"
        "<thead><tr><th>ID</th><th>Risiko</th><th>Quelle</th>"
        "<th>Behandlung</th><th>Empfehlung aus dem Fund</th><th>Eigentümer</th>"
        "<th>Frist</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        f"<p>Fristen und Budgets sind {_ph(PLACEHOLDER)}, sofern nicht organisatorisch festgelegt.</p>"
    )


def _measures_plan_table(reg: list[dict]) -> str:
    if not reg:
        return f'<p class="nodata">{NO_DATA}.</p>'
    rows = []
    for r in reg:
        rec = r.get("recommendation") or r.get("title") or PLACEHOLDER
        testhint = "Testlauf (eigenes System)" if is_selftest(r) else ""
        rows.append(
            "<tr>"
            f"<td class='num'>{_esc(r.get('id'))}</td>"
            f"<td>{_esc(rec)}"
            f"{'<br><small>'+_esc(testhint)+'</small>' if testhint else ''}</td>"
            f"<td>{_esc((r.get('queen') or '').upper())} · {_esc(r.get('title'))}</td>"
            f"<td>{_ph(r.get('owner'))}</td>"
            f"<td>{_esc(r.get('treatment') or PLACEHOLDER)}</td>"
            f"<td>{_ph(PLACEHOLDER)}</td>"
            "</tr>"
        )
    return (
        "<table class='wide measures'><colgroup><col class='c-id'><col class='c-rec'><col class='c-src'>"
        "<col class='c-owner'><col class='c-treat'><col class='c-due'></colgroup>"
        "<thead><tr><th>ID</th><th>Maßnahme / Empfehlung</th>"
        "<th>Quelle</th><th>Eigentümer</th><th>Behandlung</th><th>Status / Termin</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _raci_table(org: dict) -> str:
    roles = [
        ("Geschäftsleitung", PLACEHOLDER),
        ("ISMS-Verantwortliche/r", org_value(org, "isms_manager")),
        ("Risikoeigentümer", org_value(org, "risk_owner_default")),
        ("IT-Betrieb / Fachbereich", PLACEHOLDER),
        ("Interne Revision", PLACEHOLDER),
    ]
    activities = [
        "Leitlinie freigeben (5.2)",
        "Risikobewertung durchführen (6.1.2)",
        "Risikobehandlung steuern (6.1.3)",
        "SoA pflegen",
        "Ziele festlegen (6.2)",
        "Awareness und Kompetenz (7.2/7.3)",
        "Betrieb steuern (8.1)",
        "Internes Audit (9.2)",
        "Managementbewertung (9.3)",
        "Korrekturmaßnahmen (10.2)",
    ]
    head = "<tr><th>Tätigkeit</th>" + "".join(f"<th>{_esc(n)}<br><small>{_ph(v)}</small></th>" for n, v in roles) + "</tr>"
    body = "".join(
        "<tr><td>" + _esc(act) + "</td>" + "".join(f"<td>{_ph(PLACEHOLDER)}</td>" for _ in roles) + "</tr>"
        for act in activities
    )
    return (
        "<p>RACI (Responsible / Accountable / Consulted / Informed). "
        "Zellen sind Vorlagen und werden nicht automatisch belegt, "
        f"solange die Organisation keine Zuordnung dokumentiert ({_esc(PLACEHOLDER)}).</p>"
        f"<table class='wide raci'><colgroup><col class='c-act'></colgroup><thead>{head}</thead><tbody>{body}</tbody></table>"
        f"<p>Weitere Rollenbeschreibung: {_ph(org_value(org, 'roles_text'))}</p>"
    )


def _policy_outline(org: dict) -> str:
    rows = [
        ("Titel der Leitlinie", org_value(org, "policy_title")),
        ("Zweck und Bekenntnis zur Informationssicherheit", org_value(org, "policy_text")),
        ("Geltungsbereich der Leitlinie", org_value(org, "isms_scope")),
        ("Rahmen für Informationssicherheitsziele (6.2)", PLACEHOLDER),
        ("Verpflichtung zur Erfüllung anwendbarer Anforderungen", PLACEHOLDER),
        ("Verpflichtung zur kontinuierlichen Verbesserung", PLACEHOLDER),
        ("Freigabe durch", org_value(org, "policy_approved_by")),
        ("Freigabedatum", org_value(org, "policy_approved_on")),
        ("Kommunikation und Verfügbarkeit für interessierte Parteien", PLACEHOLDER),
        ("Regelmäßige Überprüfung", PLACEHOLDER),
    ]
    body = "".join(f"<tr><td>{_esc(k)}</td><td>{_ph(v)}</td></tr>" for k, v in rows)
    return (
        "<p>Pflichtinhalte einer Leitlinie nach ISO/IEC 27001:2022 Klausel 5.2. "
        "Vorhandene Angaben stammen aus der Organisationsmaske; fehlende bleiben "
        f"{_esc(PLACEHOLDER)}.</p>"
        "<table class='wide'><thead><tr><th>Pflichtinhalt (5.2)</th><th>Angabe</th></tr></thead>"
        f"<tbody>{body}</tbody></table>"
    )


def _asset_inventory(targets: list[dict]) -> str:
    if not targets:
        return f'<p class="nodata">{NO_DATA} — in der App sind keine Ziele oder Scope-Einträge vorhanden.</p>'
    rows = []
    for t in targets:
        scopes = t.get("scopes") or []
        testhint = "Testlauf (eigenes System)" if is_selftest(t) or is_selftest({"asset": t.get("name", "")}) else ""
        if not scopes:
            rows.append(
                "<tr>"
                f"<td>{_esc(t.get('name') or t.get('id'))}"
                f"{'<br><small>'+_esc(testhint)+'</small>' if testhint else ''}</td>"
                f"<td>{_esc(t.get('description') or NO_DATA)}</td>"
                f"<td>{_ph(NO_DATA)}</td><td>{_ph(NO_DATA)}</td>"
                f"<td>{_ph(NO_DATA)}</td><td>{_ph(PLACEHOLDER)}</td>"
                "</tr>"
            )
            continue
        for s in scopes:
            allowed = s.get("allowed")
            if allowed in (1, True, "1"):
                al = "ja (in Scope)"
            elif allowed in (0, False, "0"):
                al = "nein (außer Scope)"
            else:
                al = NO_DATA
            rows.append(
                "<tr>"
                f"<td>{_esc(t.get('name') or t.get('id'))}"
                f"{'<br><small>'+_esc(testhint)+'</small>' if testhint else ''}</td>"
                f"<td>{_esc(t.get('description') or NO_DATA)}</td>"
                f"<td>{_esc(s.get('kind') or NO_DATA)}</td>"
                f"<td>{_esc(s.get('value') or NO_DATA)}</td>"
                f"<td>{_esc(al)}</td><td>{_ph(PLACEHOLDER)}</td>"
                "</tr>"
            )
    return (
        "<p>Das Inventar wird ausschließlich aus den in der App erfassten Zielen "
        "und Scope-Einträgen gespeist. Eigentümer und Klassifizierung bleiben "
        f"{_esc(PLACEHOLDER)}, sofern nicht hinterlegt.</p>"
        "<table class='wide'><thead><tr><th>Ziel</th><th>Beschreibung</th>"
        "<th>Scope-Art</th><th>Scope-Wert</th><th>In Scope</th><th>Eigentümer</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def render_html(bundle: dict, kind: str = "isms") -> str:
    org = bundle["org"]
    th = int(org["acceptance_threshold"])
    counts = bundle["counts"]
    title = {
        "isms": "ISMS-Paket nach ISO/IEC 27001:2022",
        "red": "Red Queen — Pentest-Bericht",
        "blue": "Blue Queen — Härtungs- und Abwehrbericht",
        "yellow": "Yellow Queen — Reverse-Engineering-Bericht",
    }.get(kind, "Bericht")

    parts = [f"<!doctype html><html lang='de'><head><meta charset='utf-8'>"
             f"<title>{_esc(title)}</title><style>{_CSS}</style></head><body>"]

    parts.append(f"""
<section class="cover">
  <p class="eyebrow">antbb · All and One</p>
  <h1>{_esc(title)}</h1>
  <p>{_ph(org_value(org, "org_name"))}</p>
  <p class="meta">Erstellt: {_esc(bundle['generated_at'])}</p>
  <div class="disclaimer">{_esc(bundle['disclaimer'])}</div>
</section>
""")

    if kind in ("isms", "red", "blue", "yellow"):
        parts.append("<h2>Management Summary</h2>")
        reg_q = group_by_queen(bundle["register"])
        lines = {
            "red": f"Red-Funde {counts['red']}, davon im Risikoregister {len(reg_q.get('red') or [])}",
            "blue": (f"Blue-Prüfungen {counts['blue']} (davon offen/fehlgeschlagen {counts['blue_fail']}), "
                     f"im Risikoregister {len(reg_q.get('blue') or [])}"),
            "yellow": f"Yellow-Fälle {counts['yellow']}, im Risikoregister {len(reg_q.get('yellow') or [])}",
        }
        shown = QUEEN_ORDER if kind == "isms" else (kind,)
        parts.append("<p>Dokumentierte Daten aus der Anwendung, getrennt nach Königin:</p><ul>"
                     + "".join(f"<li>{_qtag(q)} {_esc(lines[q])}</li>" for q in shown) + "</ul>")
        if kind == "isms":
            parts.append(
                f"<p>Ziele {counts['targets']}. Risikoregister-Einträge gesamt {counts['register']}. "
                f"SoA über {counts['soa']} Annex-A-Controls.</p>"
            )
        if counts["register"] == 0 and kind == "isms":
            parts.append(f"<p class='nodata'>{NO_DATA} für bewertete Risiken aus App-Läufen.</p>")

    if kind == "isms":
        parts.append("<h2>1. Kontext und Geltungsbereich (Kap. 4)</h2>")
        parts.append(f"<p><strong>Organisation:</strong> {_ph(org_value(org, 'org_name'))}<br>"
                     f"<strong>Rechtsträger:</strong> {_ph(org_value(org, 'legal_entity'))}<br>"
                     f"<strong>Geltungsbereich:</strong> {_ph(org_value(org, 'isms_scope'))}</p>")
        parts.append(f"<p><strong>Interne Themen (4.1):</strong> {_ph(org_value(org, 'context_internal'))}<br>"
                     f"<strong>Externe Themen (4.1):</strong> {_ph(org_value(org, 'context_external'))}<br>"
                     f"<strong>Interessierte Parteien (4.2):</strong> {_ph(org_value(org, 'interested_parties'))}</p>")
        if bundle["targets"]:
            lis = "".join(
                f"<li>{_esc(_g(t,'name', _g(t,'id')))} — Scope-Einträge: "
                f"{_esc(_g(t,'scope_count', NO_DATA))}</li>"
                for t in bundle["targets"]
            )
            parts.append(f"<p>In der App erfasste Ziele (Fakten, kein erweiterter Scope):</p><ul>{lis}</ul>")
        else:
            parts.append(f"<p class='nodata'>App-Ziele: {NO_DATA}.</p>")

        parts.append("<h2>2. ISMS-Leitlinie (5.2)</h2>")
        parts.append(_policy_outline(org))

        parts.append("<h2>3. Rollen</h2>")
        parts.append(_raci_table(org))

        parts.append("<h2>4. Risikobewertungsmethodik (6.1.2)</h2>")
        parts.append(
            "<p>5×5-Matrix: Eintrittswahrscheinlichkeit × Auswirkung. "
            "Der Score ist das Produkt (1–25). "
            f"Default-Akzeptanzschwelle: Score ≥ {th} gilt als nicht akzeptabel, "
            "solange die Organisation keine eigene Schwelle festlegt"
            f"{' (Default aktiv)' if org.get('_threshold_is_default') else ''}.</p>"
        )
        parts.append(
            "<p>Sofern kein gesondertes Assessment vorliegt, werden L und I "
            "transparent aus der dokumentierten Fund-Severity abgeleitet. "
            "Das ist ein Methoden-Default, kein erfundenes Expertenurteil.</p>"
        )
        parts.append(_matrix_html(th))

        has_reg = bool(bundle["register"])
        soa_intro = (
            "<p class='lead'>Alle 93 Controls sind aufgeführt. Anwendbarkeit ist standardmäßig "
            "„ja“, solange die Organisation keine begründete Ausnahme dokumentiert. "
            "Umsetzungsstatus und Nachweis stammen nur aus App-Funden bzw. "
            f"bestandenen Blue-Prüfungen; sonst {_esc(NO_DATA)}. Nachweise sind je Zeile "
            "strikt nach Königin getrennt (RED / BLUE / YELLOW).</p>"
            '<p class="footnote"><strong>Fußnote Anwendbarkeit:</strong> '
            "„ja (Default)“ bedeutet: das Control gilt als anwendbar, "
            "solange die Organisation keine begründete Ausnahme als "
            f"{_esc(PLACEHOLDER)} dokumentiert.</p>"
        )
        sep_note = ("<p class='lead'>Getrennt nach Königin: Red-Einträge nur unter Red, "
                    "Blue nur unter Blue, Yellow nur unter Yellow. Innerhalb einer "
                    "Königin nach Score absteigend.</p>")
        # Wide tables (register when filled, always the 93-row SoA) use a named
        # landscape page. A mid-page orientation switch is physically impossible,
        # so the following portrait chapters start on a new page. Each chapter
        # and each Queen sub-section starts on its own sheet.
        if not has_reg:
            parts.append("<h2>5. Risikoregister und Behandlung (6.1.3)</h2>")
            parts.append(_register_table(bundle["register"]))
            parts.append("<h2>6. Risikobehandlungsplan</h2>")
            parts.append(_treatment_plan_table(bundle["register"]))
        parts.append('<div class="page-landscape">')
        if has_reg:
            parts.append('<h2 class="new-sheet">5. Risikoregister und Behandlung (6.1.3)</h2>')
            parts.append(sep_note)
            parts.append(_per_queen(bundle["register"], "5", "Risikoregister",
                                    _register_table, "keine Register-Einträge"))
            parts.append('<h2 class="new-sheet">6. Risikobehandlungsplan</h2>')
            parts.append(sep_note)
            parts.append(_per_queen(bundle["register"], "6", "Risikobehandlungsplan",
                                    _treatment_plan_table, "keine Einträge im Behandlungsplan"))
        parts.append('<h2 class="new-sheet">7. Statement of Applicability (Anhang A, 93 Controls)</h2>')
        parts.append(soa_intro)
        parts.append(_soa_table(bundle["soa"]))
        parts.append("</div>")

        parts.append('<div class="page-portrait">')
        parts.append('<section class="keep">')
        parts.append("<h2>8. Informationssicherheitsziele (6.2)</h2>")
        parts.append(
            "<p>Vorlage nach Klausel 6.2. Ziele, messbare Kriterien, Ressourcen, "
            "Verantwortlichkeiten, Fristen und die Art der Bewertung sind "
            f"{_ph(PLACEHOLDER)}, sofern die Organisation sie nicht in der "
            "Organisationsmaske oder einem externen Zielkatalog hinterlegt. "
            "Es werden keine Ziele erfunden.</p>"
        )
        parts.append(
            "<table class='wide'><thead><tr><th>Ziel</th><th>Messgröße</th>"
            "<th>Verantwortlich</th><th>Frist</th><th>Status</th></tr></thead><tbody>"
            f"<tr><td>{_ph(PLACEHOLDER)}</td><td>{_ph(PLACEHOLDER)}</td>"
            f"<td>{_ph(org_value(org, 'isms_manager'))}</td>"
            f"<td>{_ph(PLACEHOLDER)}</td><td>{_ph(PLACEHOLDER)}</td></tr>"
            "</tbody></table>"
        )

        parts.append('</section><section class="keep">')
        parts.append("<h2>9. Planung von Änderungen (6.3)</h2>")
        parts.append(
            "<p>Vorlage nach Klausel 6.3: Änderungen am ISMS werden geplant. "
            "Zweck, Auswirkungen, Ressourcen, Verantwortlichkeiten, Zeitplan und "
            f"Kommunikation sind {_ph(PLACEHOLDER)}, solange kein Änderungsantrag "
            "dokumentiert ist. Es wird kein Änderungsprotokoll erfunden.</p>"
        )
        parts.append(
            "<table class='wide'><thead><tr><th>Änderung</th><th>Zweck / Auswirkung</th>"
            "<th>Verantwortlich</th><th>Zeitplan</th><th>Status</th></tr></thead><tbody>"
            f"<tr><td>{_ph(PLACEHOLDER)}</td><td>{_ph(PLACEHOLDER)}</td>"
            f"<td>{_ph(PLACEHOLDER)}</td><td>{_ph(PLACEHOLDER)}</td>"
            f"<td>{_ph(PLACEHOLDER)}</td></tr>"
            "</tbody></table>"
        )

        parts.append('</section><section class="keep">')
        parts.append("<h2>10. Asset-Inventar</h2>")
        parts.append(_asset_inventory(bundle["targets"]))

        parts.append('</section><section class="keep">')
        parts.append("<h2>11. Ressourcen, Kompetenz und Awareness (7.1 bis 7.3)</h2>")
        parts.append(
            "<p>Vorlage nach Klauseln 7.1 (Ressourcen), 7.2 (Kompetenz) und 7.3 "
            "(Awareness). Personen, Qualifikation, Schulungsnachweise und "
            f"bereitgestellte Ressourcen sind {_ph(PLACEHOLDER)}, sofern nicht "
            "gesondert dokumentiert.</p>"
        )
        parts.append(
            "<table class='wide'><thead><tr><th>Klausel</th><th>Thema</th>"
            "<th>Angabe</th></tr></thead><tbody>"
            f"<tr><td>7.1</td><td>Bereitgestellte Ressourcen</td><td>{_ph(PLACEHOLDER)}</td></tr>"
            f"<tr><td>7.2</td><td>Erforderliche Kompetenz / Nachweis</td><td>{_ph(PLACEHOLDER)}</td></tr>"
            f"<tr><td>7.3</td><td>Awareness-Maßnahmen und Schulungen</td><td>{_ph(PLACEHOLDER)}</td></tr>"
            "</tbody></table>"
        )

        parts.append('</section><section class="keep">')
        parts.append("<h2>12. Kommunikation (7.4)</h2>")
        parts.append(
            "<p>Vorlage nach Klausel 7.4: Was, wann, mit wem und wie kommuniziert "
            f"wird, ist {_ph(PLACEHOLDER)}, sofern die Organisation keinen "
            "Kommunikationsplan hinterlegt hat.</p>"
        )
        parts.append(
            "<table class='wide'><thead><tr><th>Was</th><th>Wann</th><th>Mit wem</th>"
            "<th>Wie</th><th>Verantwortlich</th></tr></thead><tbody>"
            f"<tr><td>{_ph(PLACEHOLDER)}</td><td>{_ph(PLACEHOLDER)}</td>"
            f"<td>{_ph(PLACEHOLDER)}</td><td>{_ph(PLACEHOLDER)}</td>"
            f"<td>{_ph(PLACEHOLDER)}</td></tr>"
            "</tbody></table>"
        )

        parts.append('</section><section class="keep">')
        parts.append("<h2>13. Dokumentierte Information und Lenkung (7.5)</h2>")
        parts.append(
            "<p>Vorlage nach Klausel 7.5. Dokumentenversion und Änderungshistorie "
            "dieser Vorlage: das Erstellungsdatum ist die tatsächliche Erzeugung "
            "aus der Anwendung. Frühere formale Versionen werden nicht erfunden.</p>"
        )
        parts.append(
            "<table class='wide'><thead><tr><th>Merkmal</th><th>Angabe</th></tr></thead><tbody>"
            f"<tr><td>Dokumenttitel</td><td>ISMS-Paket nach ISO/IEC 27001:2022</td></tr>"
            f"<tr><td>Dokumentdatum</td><td>{_esc(bundle['generated_at'])}</td></tr>"
            f"<tr><td>Version</td><td>{_ph(PLACEHOLDER)} (kein erfundenes Versionsnummernschema)</td></tr>"
            f"<tr><td>Freigabe / Lenkung</td><td>{_ph(org_value(org, 'policy_approved_by'))}</td></tr>"
            f"<tr><td>Speicherort / Klassifizierung</td><td>{_ph(PLACEHOLDER)}</td></tr>"
            "</tbody></table>"
        )
        parts.append(
            "<table class='wide'><thead><tr><th>Datum</th><th>Änderung</th>"
            "<th>Autor</th></tr></thead><tbody>"
            f"<tr><td>{_esc(bundle['generated_at'])}</td>"
            "<td>Automatisch erzeugt bzw. aktualisiert aus den in der App "
            "gespeicherten Red-, Blue- und Yellow-Daten (kein manuell erfundenes Protokoll).</td>"
            f"<td>antbb (automatisch)</td></tr>"
            "</tbody></table>"
        )

        parts.append("</section>")
        parts.append('<h2 class="new-sheet">14. Maßnahmenplan</h2>')
        if bundle["register"]:
            parts.append("<p class='lead'>Getrennt nach Königin; jede Königin beginnt auf einem "
                         "eigenen Blatt. Keine Maßnahme wird über eine Seite getrennt.</p>")
            parts.append(_per_queen(bundle["register"], "14", "Maßnahmen",
                                    _measures_plan_table, "keine Maßnahmen"))
        else:
            parts.append(_measures_plan_table(bundle["register"]))

        parts.append('<section class="keep new-sheet">')
        parts.append('<h2>15. Betriebliche Planung und Steuerung (8.1)</h2>')
        parts.append(
            "<p>Vorlage nach Klausel 8.1. Geplante betriebliche Steuerungen, "
            "Prozessbeschreibungen, Outsourcing-Vorgaben und die Kriterien für "
            f"die Umsetzung sind {_ph(PLACEHOLDER)}. Es werden keine "
            "Betriebsprozesse erfunden. Dokumentierte App-Läufe (Red/Blue/Yellow) "
            "gelten nur als Nachweise im Register und in der SoA, nicht als "
            "vollständige Betriebsdokumentation.</p>"
        )
        parts.append(
            "<table class='wide'><thead><tr><th>Prozess / Steuerung</th>"
            "<th>Kriterium</th><th>Verantwortlich</th><th>Nachweis</th></tr></thead><tbody>"
            f"<tr><td>{_ph(PLACEHOLDER)}</td><td>{_ph(PLACEHOLDER)}</td>"
            f"<td>{_ph(PLACEHOLDER)}</td><td>{_ph(PLACEHOLDER)}</td></tr>"
            "</tbody></table>"
        )

        parts.append('</section><section class="keep">')
        parts.append("<h2>16. Kennzahlen und Überwachung (9.1)</h2>")
        parts.append(
            f"<ul><li>Anzahl dokumentierter Red-Funde: {counts['red']}</li>"
            f"<li>Offene Blue-Fehlprüfungen: {counts['blue_fail']}</li>"
            f"<li>Yellow-Fälle: {counts['yellow']}</li>"
            f"<li>Risiken über der Akzeptanzschwelle: "
            f"{sum(1 for r in bundle['register'] if r['score'] >= th)}</li>"
            f"<li>Weitere KPIs (Verfügbarkeit, Schulungsquote, Incident-MTTD): {_ph(PLACEHOLDER)}</li></ul>"
        )

        parts.append('</section><section class="keep">')
        parts.append("<h2>17. Interne Audit-Checkliste (9.2)</h2>")
        parts.append(
            "<table class='wide audit'><colgroup><col class='c-n'><col class='c-q'><col class='c-r'></colgroup>"
            "<thead><tr><th>#</th><th>Prüffrage</th><th>Ergebnis</th></tr></thead><tbody>"
            "<tr><td>1</td><td>Ist der ISMS-Geltungsbereich dokumentiert und aktuell?</td>"
            f"<td>{_ph(PLACEHOLDER)}</td></tr>"
            "<tr><td>2</td><td>Ist die Leitlinie (5.2) freigegeben?</td>"
            f"<td>{_ph(PLACEHOLDER)}</td></tr>"
            "<tr><td>3</td><td>Ist das Risikoregister aus aktuellen Assessments gespeist?</td>"
            f"<td>{'teilweise, aus App-Läufen' if counts['register'] else _ph(NO_DATA)}</td></tr>"
            "<tr><td>4</td><td>Liegt eine vollständige SoA vor?</td>"
            f"<td>Vorlage mit 93 Controls; Umsetzungsstatus oft {_esc(NO_DATA)}</td></tr>"
            "<tr><td>5</td><td>Werden Korrekturmaßnahmen nachverfolgt (10.2)?</td>"
            f"<td>{_ph(PLACEHOLDER)}</td></tr>"
            "</tbody></table>"
            f"<p>Auditprogramm: {_ph(org_value(org, 'audit_programme'))}</p>"
        )

        parts.append('</section><section class="keep">')
        parts.append("<h2>18. Managementbewertung (9.3)</h2>")
        parts.append(
            f"<p>Vorsitz: {_ph(org_value(org, 'review_chair'))}. "
            "Input aus dieser Vorlage: Fundzahlen, offene Blue-Lücken, Risiken über der Schwelle. "
            f"Beschlüsse, Teilnehmerliste und Datum: {_ph(PLACEHOLDER)}.</p>"
        )

        parts.append('</section><section class="keep">')
        parts.append("<h2>19. Nichtkonformitäten und Korrekturmaßnahmen (10.2)</h2>")
        fails = [b for b in bundle["blue"] if b.get("status") == "fail"]
        highs = [r for r in bundle["register"] if r.get("band") == "hoch"]
        if not fails and not highs:
            parts.append(f"<p class='nodata'>{NO_DATA} — keine dokumentierten Nichtkonformitäten aus App-Läufen.</p>")
        else:
            nc = group_by_queen(fails + highs)
            for q in [q for q in QUEEN_ORDER + ("app",) if nc.get(q)]:
                parts.append(f"<p class='lead'>{_qtag(q)} <strong>{_esc(QUEEN_LABEL.get(q, q.upper()))}</strong></p>")
                parts.append("<ul>" + "".join(
                    f"<li>{_esc(x.get('title'))} ({_esc(x.get('status') or x.get('band'))})</li>"
                    for x in nc[q]
                ) + "</ul>")
            parts.append(f"<p>Ursachenanalyse, Korrektur und Wirksamkeitsprüfung: {_ph(PLACEHOLDER)}.</p>")
        parts.append("</section>")
        parts.append("</div>")  # end page-portrait; orientation cannot change mid-page
        parts.append('<h2 class="new-sheet">20. Nachweisanhang aus Red-, Blue- und Yellow-Läufen</h2>')
        parts.append("<p class='lead'>Je Königin ein eigener Abschnitt auf eigenem Blatt; "
                     "IDs absteigend, kein Eintrag wird über eine Seite getrennt.</p>")

    if kind in ("isms", "red"):
        if kind == "isms":
            parts.append(_queen_heading("20.1", "red", "Pentest-Funde", new_sheet=False))
        else:
            parts.append("<h2>Pentest-Funde (Red)</h2>")
            parts.append(f"<div class='disclaimer'>{_esc(bundle['disclaimer'])}</div>")
        parts.append(_findings_table(bundle["red"], with_cvss=True,
                                     force_new_sheet_ids=RED_FORCE_NEW_SHEET_IDS))

    if kind in ("isms", "blue"):
        if kind == "isms":
            parts.append(_queen_heading("20.2", "blue", "Härtung, Abwehr, Prüfungen", new_sheet=True))
        else:
            parts.append("<h2>Härtung und Abwehr (Blue)</h2>")
            parts.append(f"<div class='disclaimer'>{_esc(bundle['disclaimer'])}</div>")
        parts.append(_findings_table(bundle["blue"], with_cvss=False))

    if kind in ("isms", "yellow"):
        if kind == "isms":
            parts.append(_queen_heading("20.3", "yellow", "RE-Analysen", new_sheet=True))
        else:
            parts.append("<h2>Reverse-Engineering-Analysen (Yellow)</h2>")
            parts.append(f"<div class='disclaimer'>{_esc(bundle['disclaimer'])}</div>")
        parts.append(_findings_table(bundle["yellow"], with_cvss=False))

    if kind != "isms":
        # Strict separation: a Queen report maps only its own entries.
        own = [r for r in bundle["register"] if _queen_of(r) == kind]
        parts.append('<div class="page-landscape">')
        parts.append('<h2 class="new-sheet">Zuordnung zu ISO/IEC 27001:2022 Annex A</h2>')
        parts.append(f"<p class='lead'>Nur Einträge der {_esc(QUEEN_LABEL.get(kind, kind))}.</p>")
        parts.append(_register_table(own) if own else
                     f'<p class="nodata">{NO_DATA} — keine Register-Einträge dieser Königin.</p>')
        parts.append("</div>")

    parts.append("</body></html>")
    return _close_tables("\n".join(parts))


def render_pdf_bytes(html_doc: str) -> tuple[Optional[bytes], str, str]:
    """Return (pdf_bytes|None, engine, note). Honest fallback if no engine."""
    engine = br.pdf_engine()
    if engine == "weasyprint":
        pdf, _eng, err = br.render_pdf_bytes(html_doc)
        if pdf:
            return pdf, "weasyprint", ""
        return None, "weasyprint", err or "WeasyPrint konnte das PDF nicht erzeugen."
    if engine == "wkhtmltopdf":
        pdf, _eng, err = br.render_pdf_bytes(html_doc)
        if pdf:
            return pdf, "wkhtmltopdf", ""
        return None, "wkhtmltopdf", err or "wkhtmltopdf konnte das PDF nicht erzeugen."
    return None, "", "Keine PDF-Engine (weasyprint oder wkhtmltopdf) installiert."


def export_csv(rows: list[dict], fieldnames: list[str]) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        flat = {}
        for k in fieldnames:
            v = r.get(k)
            if isinstance(v, (list, tuple)):
                v = "; ".join(str(x) for x in v)
            flat[k] = v
        w.writerow(flat)
    return buf.getvalue().encode("utf-8-sig")


def export_xlsx(rows: list[dict], fieldnames: list[str], sheet: str) -> Optional[bytes]:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
    except Exception:
        return None
    wb = Workbook()
    ws = wb.active
    ws.title = sheet[:31]
    header_fill = PatternFill("solid", fgColor="1B3A4B")
    header_font = Font(color="FFFFFF", bold=True)
    for col, name in enumerate(fieldnames, 1):
        cell = ws.cell(1, col, name)
        cell.fill = header_fill
        cell.font = header_font
    for r_i, r in enumerate(rows, 2):
        for c_i, name in enumerate(fieldnames, 1):
            v = r.get(name)
            if isinstance(v, (list, tuple)):
                v = "; ".join(str(x) for x in v)
            cell = ws.cell(r_i, c_i, "" if v is None else str(v))
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            if name in {"score", "band"} and r.get("color"):
                hexcol = str(r.get("color")).lstrip("#")
                if len(hexcol) == 6:
                    cell.fill = PatternFill("solid", fgColor=hexcol)
                    cell.font = Font(color="FFFFFF", bold=True)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


SOA_FIELDS = ["id", "title", "theme", "applicable", "justification", "status", "evidence"]
REGISTER_FIELDS = [
    "id", "queen", "asset", "threat", "vulnerability", "severity",
    "likelihood", "impact", "score", "band", "owner", "treatment",
    "residual", "controls", "status",
]
