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
