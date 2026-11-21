"""Remediation-Pipeline (Finding → Fix-Vorschlag → Re-Check „nachweislich geschlossen").

Nimmt ein Finding und erzeugt (1) einen konkreten, überprüfbaren Behebungs-
schritt und (2) einen RE-CHECK, der rein lesend belegt, ob die Lücke nach dem
Fix tatsächlich geschlossen ist. Der Re-Check ist non-destruktiv und liefert
einen Vorher/Nachher-Beleg (Evidence), analog zur VERIFIZIERT-Logik offensiv,
nur für den Verteidigungsfall („geschlossen").

Es wird NICHTS automatisch verändert. Die Pipeline erzeugt Fix-Vorschläge und
verifiziert den IST-Zustand; ein tatsächliches Anwenden ist ein separater,
oversight-gated Schritt außerhalb dieses Moduls.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from . import hardening as _hd
from . import softwarescan as _sw


@dataclass
class RemediationStep:
    finding_key: str
    title: str
    fix_action: str              # konkreter Behebungsschritt (Text)
    fix_command: str = ""        # optionaler Vorschlag-Befehl (nie auto-ausgeführt)
    verify_method: str = ""      # wie der Re-Check belegt
    closed: Optional[bool] = None   # True=geschlossen, False=offen, None=nicht prüfbar
    evidence: dict = field(default_factory=dict)


def _is_gap(cat: str) -> bool:
    """Alle Lücken-Kategorien der Blue-Soldaten (hardening, audit, patchmgmt, …)."""
    return cat == "blue-hardening-gap" or (cat.startswith("blue-") and cat.endswith("-gap"))


def _recheck_domain(ev: dict):
    """Re-Check eines Gaps der erweiterten Soldaten. Liefert CheckResult oder None.

    * blue-audit-gap  (evidence.audit = Modulname): modulweite collect() erneut.
    * blue-<domain>-gap (evidence.domain/check_id): antbb.blue_checks.recheck().
    """
    cid = ev.get("check_id", "")
    audit = ev.get("audit")
    try:
        if audit:
            import sys
            from .agents.blue import BLUE_AGENTS
            for cls in BLUE_AGENTS:
                if getattr(cls, "audit_id", "") == audit:
                    mod = sys.modules[cls.__module__]
                    for r in mod.collect(None, lambda a: a in ("localhost", "monitoring", "decoy")):
                        if r.check_id == cid:
                            return r
                    return None
        from . import blue_checks as _bc
        if _bc.is_domain_check(cid):
            return _bc.recheck(cid)
    except Exception:
        return None
    return None


def plan_fix(finding: dict) -> RemediationStep:
    """Erzeugt einen konkreten Fix-Vorschlag aus einem Finding-dict."""
    cat = finding.get("category", "")
    ev = finding.get("evidence") or {}
    if isinstance(ev, str):
        ev = {}
    key = finding.get("dedup_key") or finding.get("title", "")
    title = finding.get("title", "")

    if _is_gap(cat):
        return RemediationStep(
            finding_key=key, title=title,
            fix_action=ev.get("recommendation", "Empfohlene Härtung anwenden."),
            fix_command=ev.get("fix_command", ""),
            verify_method="Check erneut rein lesend ausführen (pass = geschlossen).",
        )
    if cat == "blue-outdated-software":
        fixed = ev.get("fixed", "")
        pkg = ev.get("package", "")
        act = (f"Paket '{pkg}' auf behobene Version {fixed} aktualisieren."
               if fixed else f"Paket '{pkg}' auf eine gepatchte Version aktualisieren.")
        return RemediationStep(
            finding_key=key, title=title, fix_action=act,
            verify_method="Installierte Version erneut erfassen und mit behobener Version vergleichen.",
        )
    return RemediationStep(
        finding_key=key, title=title,
        fix_action="Konfiguration/Version gemäß Finding korrigieren.",
        verify_method="Zustand erneut rein lesend prüfen.",
    )


def verify_closed(finding: dict) -> RemediationStep:
    """Prüft rein lesend, ob die im Finding beschriebene Lücke geschlossen ist.

    Liefert einen RemediationStep mit `closed` und Vorher/Nachher-Evidence.
    Non-destruktiv; nur echter IST-Zustand, nichts erfunden.
    """
    step = plan_fix(finding)
    cat = finding.get("category", "")
    ev = finding.get("evidence") or {}
    if isinstance(ev, str):
        ev = {}

    if _is_gap(cat):
        check_id = ev.get("check_id", "")
        if cat != "blue-hardening-gap":
            r = _recheck_domain(ev)
            if r is None:
                step.closed = None
                step.evidence = {"reason": f"Re-Check für '{check_id}' nicht verfügbar."}
                return step
            step.closed = (r.status == "pass")
            step.evidence = {"recheck_status": r.status, "detail": r.detail,
                             "before": "fail", "after": r.status}
            return step
        for r in _hd.run_audit():
            if r.check_id == check_id:
                step.closed = (r.status == "pass")
                step.evidence = {"recheck_status": r.status, "detail": r.detail,
                                 "before": "fail", "after": r.status}
                return step
        step.closed = None
        step.evidence = {"reason": f"Check '{check_id}' nicht auffindbar."}
        return step

    if cat == "blue-av-infection":
        path = str(ev.get("path") or "")
        step.verify_method = ("Pfad erneut prüfen: GESCHLOSSEN nur bei ClamAV-clean "
                              "oder belegtem Quarantäne-Move.")
        if not path:
            step.closed = None
            step.evidence = {"reason": "Kein Pfad im AV-Finding."}
            return step
        from . import quarantine as _q
        rec = _q.recheck_original(
            path,
            scope_check=lambda asset, _path=path: os.path.abspath(str(asset)) == os.path.abspath(_path),
        )
        if rec.get("status") == "unavailable":
            step.closed = None
        else:
            step.closed = True if rec.get("closed") else False
        step.evidence = {"before": rec.get("before"), "after": rec.get("after"),
                         "recheck_status": rec.get("status"), "detail": rec.get("reason")}
        return step

    if cat == "blue-outdated-software":
        pkg = ev.get("package", "")
        eco = ev.get("ecosystem", "")
        old = ev.get("version", "")
        fixed = ev.get("fixed", "")
        inv = _sw.collect_inventory()
        cur = next((p.version for p in inv
                    if p.name == pkg and p.ecosystem == eco), None)
        if cur is None:
            step.closed = True  # Paket nicht mehr installiert = Angriffsfläche weg
            step.evidence = {"before": old, "after": "nicht mehr installiert"}
            return step
        if fixed and cur != old and cur >= fixed:
            step.closed = True
        elif cur != old:
            step.closed = None  # geändert, aber kein verlässlicher Vergleich
        else:
            step.closed = False
        step.evidence = {"before": old, "after": cur, "fixed_target": fixed}
        return step

    step.closed = None
    step.evidence = {"reason": "Kein automatischer Re-Check für diese Kategorie definiert."}
    return step


# ---------------------------------------------------------------------------
# verify_absent: Soll-Zustand "X ist NICHT vorhanden" aktiv gegen den IST-Zustand
# prüfen – auch ohne vorheriges Finding. Gegenstück zu verify_closed.
#
# Rein lesend (os.lstat / os.scandir / glob). Es wird NICHTS gelöscht, verschoben
# oder verändert; ein Treffer wird nur protokolliert.
# ---------------------------------------------------------------------------

ABSENCE_TYPES = ("no-exposed-artifact",)
_ABSENCE_MAX_MATCHES = 50


def _absence_key(exp: dict) -> str:
    raw = str(exp.get("id") or "").strip()
    if raw:
        return raw
    return f"{exp.get('type', '')}:{exp.get('path', '')}:{exp.get('pattern', '')}"


def _static_base(pattern: str) -> str:
    """Längster glob-freier Verzeichnis-Präfix eines Musters (für Zugriffsprüfung)."""
    parts = pattern.split(os.sep)
    base: list[str] = []
    for p in parts:
        if any(ch in p for ch in "*?["):
            break
        base.append(p)
    b = os.sep.join(base) or os.sep
    return b


def _nearest_existing_dir(path: str) -> str:
    cur = os.path.abspath(path)
    while cur and not os.path.isdir(cur):
        nxt = os.path.dirname(cur)
        if nxt == cur:
            break
        cur = nxt
    return cur


def _describe(p: str) -> dict:
    try:
        st = os.lstat(p)
    except OSError as exc:
        return {"path": p, "error": type(exc).__name__}
    import stat as _stat
    return {"path": p,
            "kind": ("symlink" if _stat.S_ISLNK(st.st_mode)
                     else "dir" if _stat.S_ISDIR(st.st_mode) else "file"),
            "size": st.st_size,
            "mode": oct(st.st_mode & 0o777),
            "world_readable": bool(st.st_mode & 0o004)}


def verify_absent(expectation: dict) -> RemediationStep:
    """Prüft rein lesend einen definierten Abwesenheits-Soll-Zustand.

    `expectation` (dict):
      * type    – aktuell nur "no-exposed-artifact"
      * path    – absoluter Pfad des Artefakts ODER Verzeichnis (mit `pattern`)
      * pattern – optional, glob-Muster relativ zu `path` (z. B. "*.apk")
      * id / title – optional, für Dedup-Key und Anzeige

    Ergebnis im Feld `closed` (bewusst gleiches Feld wie verify_closed):
      True  = Soll-Zustand bestätigt sauber (Artefakt nicht vorhanden)
      False = Soll-Zustand verletzt (Artefakt vorhanden; nur protokolliert)
      None  = nicht prüfbar (ungültige Definition / kein Lesezugriff)
    Evidence: expected_absent, observed, checked_path/checked_pattern, matches.
    Non-destruktiv; es wird nichts gelöscht oder verändert.
    """
    exp = expectation if isinstance(expectation, dict) else {}
    etype = str(exp.get("type") or "no-exposed-artifact")
    path = str(exp.get("path") or "").strip()
    pattern = str(exp.get("pattern") or "").strip()
    key = _absence_key(exp)
    title = str(exp.get("title") or
                f"Soll-Zustand: kein exponiertes Artefakt unter {os.path.join(path, pattern) if pattern else path}")
    step = RemediationStep(
        finding_key=key, title=title,
        fix_action="Kein Eingriff – reine Abwesenheits-Prüfung (Soll-Zustand).",
        verify_method=("Rein lesend prüfen (os.lstat/glob), dass das definierte "
                       "Artefakt NICHT existiert (absent = bestätigt sauber)."),
    )
    base_ev = {"type": etype, "expected_absent": True,
               "checked_path": path, "checked_pattern": pattern or None}

    if etype not in ABSENCE_TYPES:
        step.closed = None
        step.evidence = {**base_ev, "observed": "unprüfbar",
                         "reason": f"Unbekannter Soll-Zustand-Typ '{etype}'."}
        return step
    if not path or not os.path.isabs(path) or "\x00" in path:
        step.closed = None
        step.evidence = {**base_ev, "observed": "unprüfbar",
                         "reason": "Pfad fehlt oder ist nicht absolut."}
        return step
    if pattern and (os.path.isabs(pattern) or ".." in pattern.split("/")):
        step.closed = None
        step.evidence = {**base_ev, "observed": "unprüfbar",
                         "reason": "Muster muss relativ zu 'path' sein (ohne '..')."}
        return step

    full = os.path.normpath(os.path.join(path, pattern)) if pattern else os.path.normpath(path)
    # Zugriffsprüfung: Lässt sich das relevante Verzeichnis überhaupt lesen?
    probe_dir = _nearest_existing_dir(_static_base(full) if pattern else os.path.dirname(full))
    if not os.access(probe_dir, os.R_OK | os.X_OK):
        step.closed = None
        step.evidence = {**base_ev, "observed": "unprüfbar", "probe_dir": probe_dir,
                         "reason": f"Kein Lesezugriff auf '{probe_dir}' – Abwesenheit nicht belegbar."}
        return step

    matches: list[str] = []
    try:
        if pattern:
            import glob as _glob
            for m in _glob.iglob(full, recursive=("**" in pattern)):
                matches.append(m)
                if len(matches) >= _ABSENCE_MAX_MATCHES:
                    break
        elif os.path.lexists(full):
            matches.append(full)
    except OSError as exc:
        step.closed = None
        step.evidence = {**base_ev, "observed": "unprüfbar",
                         "reason": f"{type(exc).__name__}: {exc}"}
        return step

    if matches:
        step.closed = False
        step.evidence = {**base_ev, "observed": "vorhanden", "probe_dir": probe_dir,
                         "match_count": len(matches),
                         "truncated": len(matches) >= _ABSENCE_MAX_MATCHES,
                         "matches": [_describe(m) for m in matches]}
    else:
        step.closed = True
        step.evidence = {**base_ev, "observed": "nicht vorhanden", "probe_dir": probe_dir,
                         "match_count": 0, "matches": []}
    return step


def llm_suggest_remediation(finding: dict, *, svc=None, max_retries: int = 1) -> dict:
    """Gezielte LLM-Ableitung konkreter harden/remediate-Schritte (Schema + Retry).

    Tool-/Check-Ergebnisse bleiben Source of Truth. Ohne konfiguriertes LLM:
    ehrlicher fallback_no_llm mit dem klassischen plan_fix()-Schritt.
    """
    import json as _json
    step = plan_fix(finding)
    base = {
        "ok": True,
        "llm_status": "fallback_no_llm",
        "fix_action": step.fix_action,
        "fix_command": step.fix_command,
        "verify_method": step.verify_method,
        "steps": [{
            "order": 1,
            "action": step.fix_action,
            "command_suggestion": step.fix_command,
            "verify": step.verify_method,
            "reversible": True,
        }],
    }
    client = None
    try:
        from . import llm as llm_mod
        client = llm_mod.LLMClient()
        if not getattr(client, "configured", False):
            client = None
    except Exception:
        client = None
    if client is None and svc is not None:
        # BlueQueen am Service hat ggf. schon einen Client — hier nicht erzwingen
        pass
    if client is None:
        return base

    schema = {
        "steps": [
            {"order": 1, "action": "string", "command_suggestion": "string",
             "verify": "string", "reversible": True, "oversight_required": True}
        ],
        "rationale": "string",
        "risks": ["string"],
    }
    payload = {
        "title": finding.get("title"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "asset": finding.get("asset"),
        "status": finding.get("status"),
        "evidence_keys": sorted((finding.get("evidence") or {}).keys())
            if isinstance(finding.get("evidence"), dict) else [],
        "baseline_fix_action": step.fix_action,
    }
    messages = [
        {"role": "system", "content":
         "Du bist Blue-Team. Leite konkrete, reversible Harden-/Remediate-Schritte ab. "
         "Keine destruktiven Befehle, keine Secrets, kein Auto-Apply. "
         "Antworte NUR mit JSON im Schema: " + _json.dumps(schema, ensure_ascii=False)},
        {"role": "user", "content": _json.dumps(payload, ensure_ascii=False)},
    ]
    from .parseutil import parse_json_robust
    last_err = ""
    for attempt in range(max_retries + 1):
        try:
            model = None
            try:
                from . import llm as llm_mod
                model = llm_mod.select_model("remediation") if hasattr(llm_mod, "select_model") else None
            except Exception:
                model = None
            # Signatur: chat(messages, model=None, provider=None, temperature=0.2, max_tokens=1024)
            res = client.chat(messages, model, None, 0.1, 600)
        except Exception as exc:
            return {**base, "llm_status": "error", "error": f"{type(exc).__name__}: {exc}"}
        if not getattr(res, "ok", False):
            return {**base, "llm_status": "error",
                    "error": getattr(res, "error", "llm_not_ok")}
        obj, warn = parse_json_robust(res.content or "", expect=dict)
        if isinstance(obj, dict) and isinstance(obj.get("steps"), list) and obj["steps"]:
            # Schema-Sanity: nur Strings/Bools, keine Shell-Injection-Freiheit erfinden —
            # command_suggestion bleibt Vorschlag (nie auto-executed hier).
            clean_steps = []
            for i, s in enumerate(obj["steps"][:8]):
                if not isinstance(s, dict):
                    continue
                clean_steps.append({
                    "order": int(s.get("order") or (i + 1)),
                    "action": str(s.get("action") or "")[:500],
                    "command_suggestion": str(s.get("command_suggestion") or "")[:500],
                    "verify": str(s.get("verify") or "")[:500],
                    "reversible": bool(s.get("reversible", True)),
                    "oversight_required": bool(s.get("oversight_required", True)),
                })
            if not clean_steps:
                last_err = "empty_steps"
            else:
                return {
                    "ok": True,
                    "llm_status": "used",
                    "llm_model": getattr(res, "model", "") or "",
                    "llm_provider": getattr(res, "provider", "") or "",
                    "parse_warning": warn,
                    "rationale": str(obj.get("rationale") or "")[:800],
                    "risks": [str(x)[:200] for x in (obj.get("risks") or [])[:8]],
                    "steps": clean_steps,
                    "fix_action": clean_steps[0]["action"],
                    "fix_command": clean_steps[0].get("command_suggestion") or "",
                    "verify_method": clean_steps[0].get("verify") or step.verify_method,
                }
        else:
            last_err = warn or "schema_mismatch"
        messages.append({"role": "assistant", "content": (res.content or "")[:1500]})
        messages.append({"role": "user", "content":
                         "Ungültiges JSON. Nur Schema-JSON, keine Markdown-Fence."})
    status = "fallback_no_llm" if last_err in ("empty_output", "empty_steps") else "error"
    return {**base, "llm_status": status, "error": f"schema_failed:{last_err}"}
