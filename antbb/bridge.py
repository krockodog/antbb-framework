"""Red → Blue → Re-Check-Brücke (Korrelationskette + Remediation + Verify).

Einheitliche run_group_id / parent_finding_id-Kette ohne eigenen Message-Bus.
Harte Gates bleiben: Scope default-deny, Oversight für Apply/Offensive Verify.
"""
from __future__ import annotations

import json
import logging
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


def new_run_group_id() -> str:
    return "rg-" + uuid.uuid4().hex[:12]


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
    if not run_group_id:
        # aus scan_runs.meta des Ursprungs-Runs
        try:
            sr = store.get_scan_run(finding.get("run_id") or "")
            if sr:
                meta = json.loads(sr["meta"] or "{}")
                run_group_id = meta.get("run_group_id") or ""
        except Exception:
            pass
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
                "llm_plan": llm_plan,
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
                    "llm_plan": llm_plan,
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
                    "llm_plan": llm_plan, "recheck": None,
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
        # eng: nur verify-Phase, nur betroffenes Asset als Fokus
        asset = finding.get("asset") or ""
        try:
            from .active_oversight import enforce_active_oversight
            enforce_active_oversight(
                oversight_ack,
                action="Red verify Re-Check (eng begrenzt)",
                log=lambda m: log.info("%s", m),
            )
            # Scope: Verify braucht Oversight; force nicht defensive, aber phases=verify
            swarm = svc.run_scan(
                tid,
                phases=("verify",),
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
                },
            )
            # Wenn Verify neue Findings gleicher Kategorie/Asset liefert → still open
            related = [
                f for f in swarm.findings
                if (not asset or f.asset == asset)
                and f.status in ("VERIFIZIERT", "ZU BESTÄTIGEN", "BESTÄTIGT(PASSIV)")
            ]
            if related:
                outcome = STATUS_STILL_OPEN
            elif recheck.closed is True:
                outcome = STATUS_MITIGATED
            else:
                # kein neuer Beweis, alter Re-Check unklar → VERIFIED nur wenn
                # ursprünglicher Status VERIFIZIERT und nichts widerspricht
                if str(finding.get("status") or "") == "VERIFIZIERT" and recheck.closed is not True:
                    outcome = STATUS_VERIFIED
                else:
                    outcome = STATUS_STILL_OPEN
            red_verify = {
                "run_id": swarm.run_id,
                "run_group_id": run_group_id,
                "finding_count": len(swarm.findings),
                "related_open": len(related),
                "by_status": swarm.by_status(),
            }
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
        },
    )
    # Wenn mitigiert: close_finding-Pfad für blue-* (status GESCHLOSSEN parallel)
    if outcome == STATUS_MITIGATED and str(finding.get("category") or "").startswith("blue-"):
        try:
            store.close_finding(finding_id, {
                "bridge_outcome": outcome, "recheck": _step_dict(recheck),
            })
        except Exception:
            pass

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
