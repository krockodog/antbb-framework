"""Red → Blue → Re-Check-Brücke (Korrelationskette + Remediation + Verify).

Einheitliche run_group_id / parent_finding_id-Kette ohne eigenen Message-Bus.
Harte Gates bleiben: Scope default-deny, Oversight für Apply/Offensive Verify.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from typing import Any, Optional

from . import remediation
from . import scope as scope_mod

log = logging.getLogger("antbb.bridge")

# Status-Werte für Re-Check-Ausgang (additiv zu bestehenden Status-Strings)
STATUS_MITIGATED = "MITIGATED"       # geschlossen / behoben
STATUS_VERIFIED = "VERIFIED"         # Verifikation bestätigt Befund noch/weiterhin
STATUS_STILL_OPEN = "STILL_OPEN"     # Fix nicht wirksam / Befund offen

# Offensive Status, die Blue sehen darf (Filter source_colony=offensive)
OFFENSIVE_VISIBLE = frozenset({
    "VERIFIZIERT", "ZU BESTÄTIGEN", "BESTÄTIGT(PASSIV)", "BEDINGT",
    "VERIFIED", "STILL_OPEN",
})


#: Obergrenze für mitgeführte Parse-Ereignisse in Bridge-Antworten/Evidence.
MAX_PARSE_EVENTS = 20

#: Status, mit denen ein Fund im Re-Check-Lauf als "besteht weiter" zählt.
OPEN_RECHECK_STATUS = frozenset({"VERIFIZIERT", "ZU BESTÄTIGEN", "BESTÄTIGT(PASSIV)"})
#: Meta-Kategorie des engen Re-Checks (antbb.agents.recheck.RECHECK_CATEGORY).
RECHECK_CATEGORY = "recheck-result"


def related_open_findings(findings, finding: dict) -> list:
    """Funde eines Re-Check-Laufs, die GENAU diesen Befund weiter belegen (ABPM-13 B).

    Abgleich über den dedup_key des Ursprungs-Funds; nur wenn der fehlt, über
    Kategorie + Asset. Andere Funde auf demselben Host zählen NICHT (früher
    hielt jeder offene Fund auf dem Asset den Status auf STILL_OPEN).
    Meta-Funde des Re-Checks selbst werden ignoriert.
    """
    key = str(finding.get("dedup_key") or "")
    cat = str(finding.get("category") or "")
    asset = str(finding.get("asset") or "")
    out = []
    for f in findings or []:
        if getattr(f, "category", "") == RECHECK_CATEGORY:
            continue
        if getattr(f, "status", "") not in OPEN_RECHECK_STATUS:
            continue
        if key:
            f_key = f.key() if hasattr(f, "key") else getattr(f, "dedup_key", "")
            if f_key == key:
                out.append(f)
        elif getattr(f, "category", "") == cat and (not asset or getattr(f, "asset", "") == asset):
            out.append(f)
    return out


def targeted_recheck_result(findings, finding: dict) -> Optional[dict]:
    """Evidence des Meta-Funds aus dem engen Re-Check (Phase "recheck") oder None."""
    key = str(finding.get("dedup_key") or "") or \
        f"{finding.get('category')}:{finding.get('asset')}"
    for f in findings or []:
        if getattr(f, "category", "") != RECHECK_CATEGORY:
            continue
        ev = getattr(f, "evidence", None) or {}
        if ev.get("recheck_of") == key:
            return ev
    return None


def new_run_group_id() -> str:
    return "rg-" + uuid.uuid4().hex[:12]


def parse_info(evidence: Any) -> Optional[dict]:
    """parse_status/parse_warning aus einer Finding-Evidence (ABPM-12), sonst None.

    Nur gesetzt, wenn der Fund aus einer NICHT sauber geparsten Tool-Ausgabe
    stammt; bei sauberem Parse trägt die Evidence diese Felder nicht.
    """
    if not isinstance(evidence, dict):
        return None
    status = evidence.get("parse_status")
    warning = evidence.get("parse_warning")
    if not status and not warning:
        return None
    info = {"parse_status": str(status or ""), "parse_warning": str(warning or "")}
    for key in ("parse_context", "parse_method"):
        if evidence.get(key):
            info[key] = str(evidence[key])
    return info


def _red_verify_parse(swarm) -> dict:
    """Parse-Lage eines Red-Verify-Laufs: Adapter-Ereignisse + betroffene Funde."""
    events = list(getattr(swarm, "parse_events", None) or [])
    degraded_findings = sum(
        1 for f in (getattr(swarm, "findings", None) or [])
        if parse_info(getattr(f, "evidence", None)))
    return {
        "parse_degraded": bool(events or degraded_findings),
        "parse_event_count": len(events),
        "parse_events": events[:MAX_PARSE_EVENTS],
        "parse_degraded_findings": degraded_findings,
    }


def colony_of_run_id(run_id: Optional[str]) -> str:
    r = (run_id or "").strip().lower()
    if r.startswith("blue-") or r.startswith("blue_"):
        return "blue"
    if r.startswith("yellow-") or r.startswith("yq-"):
        return "yellow"
    return "offensive"


def finding_source_colony(row: Any) -> str:
    """Liest source_colony aus Row/dict; Fallback aus run_id/agent."""
    try:
        sc = row["source_colony"] if "source_colony" in row.keys() else ""
    except Exception:
        sc = (row.get("source_colony") if isinstance(row, dict) else "") or ""
    if sc:
        return str(sc)
    try:
        agent = row["agent"] if not isinstance(row, dict) else row.get("agent")
        run_id = row["run_id"] if not isinstance(row, dict) else row.get("run_id")
    except Exception:
        agent, run_id = "", ""
    agent = (agent or "").lower()
    if agent.startswith("blue-") or agent.startswith("blue_"):
        return "blue"
    return colony_of_run_id(run_id)


def list_blue_visible_findings(store, *, source_colony: str = "blue",
                               status_filter: Optional[list[str]] = None,
                               require_scope: bool = True) -> list[dict]:
    """Blue-Remediation-Liste: blue-* ODER source_colony=offensive (gefiltert).

    - source_colony='blue' (Default): bisheriges Verhalten (category startswith blue-).
    - source_colony='offensive': Red-Funde mit Status verified/to_confirm + Scope-Check.
    - source_colony='all': beides.
    """
    sc = (source_colony or "blue").strip().lower()
    want_status = None
    if status_filter:
        want_status = {s.strip() for s in status_filter if s and s.strip()}
    rows: list[dict] = []
    for row in store.list_findings():
        item = dict(row)
        # evidence JSON → dict
        ev = item.get("evidence") or {}
        if isinstance(ev, str):
            try:
                ev = json.loads(ev)
            except json.JSONDecodeError:
                ev = {}
        item["evidence"] = ev
        # ABPM-13: Herkunft aus teilweise unlesbarer Tool-Ausgabe sofort sichtbar.
        pinfo = parse_info(ev)
        if pinfo:
            item["parse_status"] = pinfo["parse_status"]
            item["parse_warning"] = pinfo["parse_warning"]
        cat = str(item.get("category") or "")
        is_blue = cat.startswith("blue-")
        colony = finding_source_colony(item)
        item["source_colony"] = colony

        if sc == "blue":
            if not is_blue:
                continue
        elif sc == "offensive":
            if is_blue or colony == "blue":
                continue
            st = str(item.get("status") or "")
            if want_status:
                if st not in want_status:
                    continue
            elif st not in OFFENSIVE_VISIBLE:
                continue
            if require_scope:
                tid = item.get("target_id")
                asset = item.get("asset") or ""
                if tid is None:
                    continue
                # Scope-Check: Asset muss in Allowlist sein (default-deny)
                if asset and asset not in ("localhost", "monitoring", "decoy"):
                    try:
                        ok = bool(scope_mod.check_asset(store, int(tid), asset))
                    except Exception:
                        ok = False
                    if not ok:
                        item["scope_ok"] = False
                        # trotzdem auflisten, aber markiert — Apply bleibt gated
                    else:
                        item["scope_ok"] = True
                else:
                    item["scope_ok"] = True
        elif sc == "all":
            if not is_blue:
                st = str(item.get("status") or "")
                if want_status and st not in want_status:
                    continue
                if not want_status and st and st not in OFFENSIVE_VISIBLE and colony != "blue":
                    # leere Status bei blue schon oben; offensive ohne Status raus
                    if colony == "offensive" and st not in OFFENSIVE_VISIBLE:
                        continue
        else:
            continue
        rows.append(item)
    return rows


def remediate_and_recheck(
    svc,
    finding_id: int,
    *,
    oversight_ack: Optional[bool] = None,
    apply_fix: bool = False,
    trigger_red_verify: bool = True,
    payload: Optional[dict] = None,
) -> dict:
    """Kontrollierter Fix + optional eng begrenzter Red-Verify auf das Finding.

    Gates:
      - apply_fix=True → Oversight-Ack + Target-Oversight (wie /apply).
      - trigger_red_verify → Red Queen nur Phase 'verify', active=True,
        nur wenn Oversight bestätigt; Scope bleibt hart.
    """
    payload = dict(payload or {})
    store = svc.store
    row = store.get_finding(int(finding_id))
    if row is None:
        return {"ok": False, "error": "finding_missing", "finding_id": finding_id}
    finding = dict(row)
    ev = finding.get("evidence") or {}
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except json.JSONDecodeError:
            ev = {}
    finding["evidence"] = ev
    source_parse = parse_info(ev)   # Fund stammt aus teilweise unlesbarer Ausgabe?
    tid = int(finding["target_id"])
    parent_id = int(finding_id)
    # Korrelationskette: bestehende run_group_id übernehmen oder neu
    run_group_id = ""
    try:
        run_group_id = (finding.get("run_group_id") or "") if isinstance(finding, dict) else ""
        if not run_group_id and "run_group_id" in row.keys():
            run_group_id = row["run_group_id"] or ""
    except Exception:
        run_group_id = ""
    warnings: list[str] = []
    if not run_group_id:
        # aus scan_runs.meta des Ursprungs-Runs
        try:
            sr = store.get_scan_run(finding.get("run_id") or "")
            if sr:
                meta = json.loads(sr["meta"] or "{}")
                run_group_id = (meta.get("run_group_id") or "") if isinstance(meta, dict) else ""
        except (json.JSONDecodeError, TypeError, KeyError, IndexError, sqlite3.Error) as exc:
            msg = (f"run_group_id aus scan_runs.meta (run {finding.get('run_id')!r}) nicht "
                   f"lesbar: {type(exc).__name__}: {exc} – neue Korrelations-ID vergeben.")
            log.warning("%s", msg)
            warnings.append(msg)
    if not run_group_id:
        run_group_id = new_run_group_id()

    step = remediation.plan_fix(finding)
    # optional LLM-abgeleitete Harden/Remediate-Schritte (Schema-geprüft)
    llm_plan = None
    try:
        llm_plan = remediation.llm_suggest_remediation(finding, svc=svc)
    except Exception as exc:
        llm_plan = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    apply_result = None
    if apply_fix:
        from .active_oversight import enforce_active_oversight
        from .oversight import OversightError
        try:
            enforce_active_oversight(
                oversight_ack,
                action="Blue Remediation Apply + Re-Check",
                log=lambda m: log.info("%s", m),
            )
            if not store.is_confirmed(tid):
                raise OversightError("Target-Oversight fehlt – Apply blockiert.")
        except Exception as exc:
            return {
                "ok": False, "error": str(exc), "finding_id": finding_id,
                "run_group_id": run_group_id, "step": _step_dict(step),
                "llm_plan": llm_plan, "warnings": warnings,
            }
        cat = str(finding.get("category") or "")
        if cat.startswith("blue-"):
            from . import remediation_apply
            try:
                apply_result = remediation_apply.apply_fix(finding, {
                    **payload, "oversight_ack": True,
                })
            except remediation_apply.RemediationError as exc:
                return {
                    "ok": False, "error": str(exc), "finding_id": finding_id,
                    "run_group_id": run_group_id, "step": _step_dict(step),
                    "llm_plan": llm_plan, "warnings": warnings,
                }
            if apply_result.get("closed") is True:
                store.close_finding(finding_id, apply_result)
                store.update_finding_bridge(
                    finding_id, status=STATUS_MITIGATED,
                    run_group_id=run_group_id, parent_finding_id=None,
                    source_finding_id=parent_id,
                    extra_evidence={"remediation_apply": apply_result,
                                   "run_group_id": run_group_id},
                )
                return {
                    "ok": True, "finding_id": finding_id,
                    "run_group_id": run_group_id,
                    "outcome": STATUS_MITIGATED,
                    "apply": apply_result, "step": _step_dict(step),
                    "llm_plan": llm_plan, "recheck": None, "warnings": warnings,
                }
        else:
            # Offensive Funde: kein auto-apply über blue SUPPORTED-Checks —
            # nur Plan + optional Red-Verify. Explizit dokumentiert.
            apply_result = {
                "applied": False,
                "reason": "offensive_finding_no_auto_apply",
                "hint": "Mitigation manuell/über Blue-Härtung; Re-Check via Red verify.",
            }

    # Re-Check: erst Blue verify_closed, dann optional eng begrenzter Red-Verify
    recheck = remediation.verify_closed(finding)
    outcome = STATUS_STILL_OPEN
    if recheck.closed is True:
        outcome = STATUS_MITIGATED
    elif recheck.closed is False:
        outcome = STATUS_STILL_OPEN
    elif recheck.closed is None and not trigger_red_verify:
        outcome = STATUS_STILL_OPEN

    red_verify = None
    if trigger_red_verify and outcome != STATUS_MITIGATED:
        asset = finding.get("asset") or ""
        # A: Für bekannte Red-Arten genau diesen Befund erneut prüfen (Phase
        # "recheck", RecheckAnt); sonst wie bisher die verify-Phase. Beides läuft
        # über svc.run_scan -> Scope-/Oversight-/mode_policy-Gates unverändert.
        spec = remediation.red_recheck_spec(finding)
        try:
            from .active_oversight import enforce_active_oversight
            enforce_active_oversight(
                oversight_ack,
                action="Red Re-Check (eng begrenzt)",
                log=lambda m: log.info("%s", m),
            )
            swarm = svc.run_scan(
                tid,
                phases=("recheck",) if spec else ("verify",),
                active=True,
                fuzz=False,
                offensive=False,
                oversight_ack=True if oversight_ack is True else oversight_ack,
                use_llm=False,
                run_group_id=run_group_id,
                parent_finding_id=parent_id,
                task_params={
                    "focus_asset": asset,
                    "parent_finding_id": parent_id,
                    "recheck_of": finding.get("dedup_key") or finding.get("title"),
                    **({"recheck": spec} if spec else {}),
                },
            )
            # B: nur Funde, die GENAU diesen Befund belegen (dedup_key).
            related = related_open_findings(swarm.findings, finding)
            parse_state = _red_verify_parse(swarm)
            targeted = targeted_recheck_result(swarm.findings, finding) if spec else None
            reproduced = targeted.get("reproduced") if targeted else None
            # Ein "nicht mehr vorhanden" zählt nur bei sauber lesbaren Ausgaben.
            cleanly_absent = reproduced is False and not parse_state["parse_degraded"]
            if related or reproduced is True:
                outcome = STATUS_STILL_OPEN
            elif recheck.closed is True or cleanly_absent:
                outcome = STATUS_MITIGATED
            else:
                # kein neuer Beweis, Re-Check unklar → VERIFIED nur wenn
                # ursprünglicher Status VERIFIZIERT und nichts widerspricht
                if str(finding.get("status") or "") == "VERIFIZIERT" and recheck.closed is not True:
                    outcome = STATUS_VERIFIED
                else:
                    outcome = STATUS_STILL_OPEN
            red_verify = {
                "run_id": swarm.run_id,
                "run_group_id": run_group_id,
                "mode": "targeted" if spec else "verify-phase",
                "match": "dedup_key" if finding.get("dedup_key") else "category+asset",
                "finding_count": len(swarm.findings),
                "related_open": len(related),
                "by_status": swarm.by_status(),
                **parse_state,
            }
            if spec:
                red_verify["recheck_kind"] = spec["kind"]
                red_verify["reproduced"] = reproduced
                red_verify["recheck_detail"] = (targeted or {}).get("detail") or {
                    "reason": "kein Re-Check-Ergebnis im Lauf (Gate/Fehler, siehe Lauf-Log)"}
            if parse_state["parse_degraded"] and not related and reproduced is not True:
                # Ausgang bleibt wie berechnet; nur ehrlich kennzeichnen.
                red_verify["note"] = (
                    "Re-Check ohne Gegenbefund, aber Tool-Ausgaben waren teilweise "
                    "unlesbar (parse_warning) – fehlende Funde sind kein Nachweis.")
        except Exception as exc:
            red_verify = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    # Persistenz: Status + Korrelation am Parent-Finding
    store.update_finding_bridge(
        finding_id,
        status=outcome if outcome != STATUS_VERIFIED else (
            "VERIFIZIERT" if str(finding.get("status") or "") == "VERIFIZIERT" else outcome
        ),
        run_group_id=run_group_id,
        parent_finding_id=None,
        source_finding_id=parent_id,
        extra_evidence={
            "recheck": _step_dict(recheck),
            "red_verify": red_verify,
            "run_group_id": run_group_id,
            "bridge_outcome": outcome,
            "apply": apply_result,
            "llm_plan": llm_plan,
            **({"source_parse": source_parse} if source_parse else {}),
        },
    )
    # Wenn mitigiert: close_finding-Pfad für blue-* (status GESCHLOSSEN parallel)
    if outcome == STATUS_MITIGATED and str(finding.get("category") or "").startswith("blue-"):
        try:
            store.close_finding(finding_id, {
                "bridge_outcome": outcome, "recheck": _step_dict(recheck),
            })
        except Exception as exc:  # Status MITIGATED ist bereits persistiert
            msg = (f"close_finding({finding_id}) fehlgeschlagen: {type(exc).__name__}: {exc} "
                   "– Status MITIGATED gesetzt, GESCHLOSSEN-Markierung fehlt.")
            log.warning("%s", msg)
            warnings.append(msg)

    return {
        "ok": True,
        "finding_id": finding_id,
        "run_group_id": run_group_id,
        "outcome": outcome,
        "step": _step_dict(step),
        "recheck": _step_dict(recheck),
        "red_verify": red_verify,
        "apply": apply_result,
        "llm_plan": llm_plan,
        "source_parse": source_parse,
        "warnings": warnings,
    }


def _step_dict(step) -> dict:
    if step is None:
        return {}
    if isinstance(step, dict):
        return step
    return {
        "finding_key": getattr(step, "finding_key", ""),
        "title": getattr(step, "title", ""),
        "fix_action": getattr(step, "fix_action", ""),
        "fix_command": getattr(step, "fix_command", ""),
        "verify_method": getattr(step, "verify_method", ""),
        "closed": getattr(step, "closed", None),
        "evidence": getattr(step, "evidence", {}) or {},
    }
