"""Die Queen: classify → Toolchain wählen → Soldaten spawnen → mergen (Dossier/Ledger/Brain) – mit Erklärbär je Hop."""
from __future__ import annotations

import re
import shutil
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import config, db
from ..gates import GATE_TEXT_DE, GateResult
from ..soldiers import REGISTRY
from ..soldiers.base import Ctx
from . import classify as clf
from . import flow, neural_brain, reports, router

_NOTES_LOCK = threading.Lock()


def safe_filename(name: str | None) -> str:
    n = Path((name or "sample.bin").replace("\\", "/")).name
    n = re.sub(r"[^A-Za-z0-9._ -]", "_", n).strip(" .") or "sample.bin"
    return n[:100]


def create_case(tmp_file: Path, filename: str | None, gate: GateResult) -> dict[str, Any]:
    """Legt Fall + Verzeichnis an. Wird nur NACH bestandenem Autorisierungs-Gate aufgerufen."""
    config.ensure_dirs()
    sha, _md5, size = clf.hashes(tmp_file)
    cid = f"yq-{datetime.now(config.TZ).strftime('%Y%m%d-%H%M%S')}-{sha[:8]}"
    n = 1
    while (config.CASES_DIR / cid).exists():
        n += 1
        cid = f"yq-{datetime.now(config.TZ).strftime('%Y%m%d-%H%M%S')}-{sha[:8]}-{n}"
    case_dir = config.CASES_DIR / cid
    ev = case_dir / "evidence"
    ev.mkdir(parents=True)
    shutil.move(str(tmp_file), ev / "sample.bin")
    row = {"id": cid, "filename": safe_filename(filename), "sha256": sha, "size": size, "kind": "?", "route": "?", "packed": 0,
           "status": "queued", "dynamic": gate.dynamic, "authorized": 1, "oversight": int(gate.oversight),
           "case_path": str(case_dir), "created_at": config.now_iso(), "updated_at": config.now_iso()}
    db.insert_case(row)
    db.add_event(cid, "case", "Fall angelegt (autorisiert bestätigt)")
    return row


def _next3_strings(route: router.Route, results: list[Any]) -> list[str]:
    out: list[str] = []
    for src in ([n for r in reversed(results) if r.name != "triage" for n in r.next] + route.next_de + [n for r in results for n in r.next]):
        if src not in out:
            out.append(src)
    return out[:3]


def run_case(case_id: str, gate: GateResult) -> dict[str, Any]:
    case = db.get_case(case_id)
    assert case, case_id
    case_dir = Path(case["case_path"])
    ev = case_dir / "evidence"
    sample = ev / "sample.bin"
    hops: list[dict] = []
    results: list[Any] = []
    blockers: list[str] = []
    state: dict[str, Any] = {"route": None}
    snap_case = {**case, "subtype": ""}

    def snapshot(phase: str, active: str | None = None, finished: bool = False, c: dict | None = None, route=None, next3: list[str] | None = None) -> None:
        last = hops[-1] if hops else None
        steps, active_step = flow.build_next3(route, c, results, hops, finished, phase=phase)
        findings = flow.extract_findings(case_id, c, results)
        bypass = flow.build_bypass(route, c, gate.dynamic, gate.oversight, finished=finished)
        dynamic_step = flow.build_dynamic(gate.dynamic, gate.oversight, results, finished=finished)
        # next3: Strings (Smoke/Ledger) + strukturierte Steps für UI
        n3_labels = next3 if next3 is not None else flow.next3_labels(steps)
        if next3 is None and route and finished:
            n3_labels = _next3_strings(route, results) or n3_labels
        last_run = findings[0]["ran_at"] if findings else config.now_iso()
        snap = {
            "brain": "yellow-neural-brain", "case_id": case_id, "sample_sha": case["sha256"], "title": case["filename"],
            "phase": phase, "active_soldier": active, "active_playbook": route.playbook if route else None, "finished": finished,
            "dynamic": gate.dynamic, "oversight": {"dynamic": gate.dynamic, "oversight_confirmed": gate.oversight, "notes": gate.notes_de},
            "hops": hops, "blockers": blockers,
            "next3": n3_labels,
            "next3_steps": steps,
            "active_step": active_step,
            "findings": findings,
            "bypass": bypass,
            "dynamic_step": dynamic_step,
            "last_ran_at": last_run,
            "classification": ({k: c[k] for k in ("kind", "subtype", "arch", "packed", "packer_hints", "entropy", "size")} if c else None),
            "erklaerbaer": ({"warum": last["warum"], "fund": last["fund"], "next": last["next"]} if last else
                            {"warum": "Gate wird geprüft.", "fund": "-", "next": ["Classify"]}),
            "dossier_path": f"/yellow/case/{case_id}/dossier.md", "ledger_path": f"/yellow/case/{case_id}/ledger.md",
            "links": {"case": f"/yellow/case/{case_id}", "dossier": f"/yellow/case/{case_id}/dossier.md", "ledger": f"/yellow/case/{case_id}/ledger.md",
                      "evidence": [f"/yellow/case/{case_id}/evidence/{f}" for r in results for f in r.evidence],
                      "canonical_brain": "http://192.168.2.7:1001/brain"},
        }
        neural_brain.write_snapshot(case_id, snap)

    def hop(op: str, skill: str, summary: str, warum: str, fund: str, nxt: list[str], status: str = "ok") -> None:
        h = {"op": op, "skill": skill, "status": status, "summary_de": summary, "warum": warum, "fund": fund, "next": nxt}
        hops.append(h)
        db.add_hop(case_id, len(hops), h)
        c = state.get("c")
        rt = state.get("route")
        steps, _ = flow.build_next3(rt, c, results, hops, False)
        reports.write_ledger(case_dir, {**snap_case, "kind": c["kind"] if c else "?", "subtype": c["subtype"] if c else ""}, rt, hops, blockers,
                             flow.next3_labels(steps) if steps else (rt.next_de[:3] if rt else ["Classify abwarten"]), gate.notes_de)

    try:
        db.update_case(case_id, status="running")
        # Phase 0 – Gate
        hop("gate", "yellow-gate", "Gate bestanden: Autorisierung bestätigt.",
            "Bevor irgendetwas analysiert wird, prüfe ich Autorisierung und Oversight – deshalb decompiliere ich noch nichts.",
            GATE_TEXT_DE + " " + " ".join(gate.notes_de),
            ["Sample klassifizieren (sha256, Magic, Packer/.NET-Hinweise)"])
        snapshot("triage")
        # Phase 1 – Classify
        snapshot("triage", active="classify")
        c = clf.classify(sample)
        state["c"] = c
        db.update_case(case_id, sha256=c["sha256"], kind=c["kind"], size=c["size"], packed=int(c["packed"]),
                       classification_json=__import__("json").dumps(c, ensure_ascii=False))
        hop("classify", "re-triage",
            f"Classify: {c['kind']} · {c['subtype'] or 'unbekannt'} · sha256 {c['sha256'][:12]}…",
            "sha256 identifiziert das Sample eindeutig; Magic-Bytes und Header sagen, welches Format es wirklich ist – unabhängig von der Dateiendung.",
            f"Format {c['kind']} ({c['subtype'] or 'unbekannt'}), Architektur {c['arch'] or 'n/a'}, Entropie {c['entropy']}. "
            + (f"Packer-Hinweise: {'; '.join(c['packer_hints'])}." if c["packer_hints"] else "Keine Packer-Hinweise."),
            ["Passende Toolchain per Entscheidungsbaum wählen"])
        snapshot("triage", c=c)
        # Phase 2 – Toolchain
        route = router.decide(c)
        state["route"] = route
        db.update_case(case_id, route=route.id)
        hop("toolchain", route.primary_skill,
            f"Route {route.id}: Primär {route.primary_skill}, Alternative {route.alternate}, Playbook {route.playbook}",
            route.warum_de, f"Nicht zuerst: {route.nicht_zuerst_de}. Soldaten: {', '.join(route.soldiers)}.",
            [f"Soldat '{route.soldiers[0]}' starten"])
        snapshot("triage", c=c, route=route)
        # Phase 3 – Soldaten
        for sname in route.soldiers:
            snapshot("static", active=sname, c=c, route=route)
            try:
                res = REGISTRY[sname](Ctx(sample, ev, c, gate.dynamic))
            except Exception as e:  # noqa: BLE001 – ein Soldat darf nie die Queen stürzen
                blockers.append(f"Soldat {sname} Fehler: {type(e).__name__}: {e}")
                hop(f"soldier:{sname}", sname, f"Soldat {sname} ist gescheitert ({type(e).__name__}).",
                    "Ein Soldat darf scheitern, ohne dass die Queen stoppt.", str(e)[:300], ["Fehler im Ledger prüfen und Soldaten erneut starten"], "error")
                (ev / f"error_{sname}.txt").write_text(traceback.format_exc(), encoding="utf-8")
                continue
            results.append(res)
            if res.tools_missing:
                blockers.append(f"{sname}: fehlende Tools → Fallback genutzt: {', '.join(sorted(set(res.tools_missing)))}")
            hop(f"soldier:{sname}", res.skill, res.summary_de, res.warum, res.fund, res.next, res.status)
            snapshot("static", active=sname, c=c, route=route)
        # Phase 3b – Dynamic Lab (Yellow führt selbst aus, nur bei yes-lab + Oversight)
        if gate.dynamic == "yes-lab" and gate.oversight:
            snapshot("dynamic", active="dynamic", c=c, route=route)
            try:
                from ..soldiers import dynamic_lab as _dyn
                res = _dyn.run(Ctx(sample, ev, c, gate.dynamic))
            except Exception as e:  # noqa: BLE001
                blockers.append(f"Dynamic-Lab Fehler: {type(e).__name__}: {e}")
                hop("soldier:dynamic", "dynamic-lab-re", f"Dynamic-Lab gescheitert ({type(e).__name__}).",
                    "Lab-Lauf mit Oversight war freigeschaltet, der Soldat ist trotzdem abgestürzt.",
                    str(e)[:300], ["Evidence error_dynamic.txt prüfen"], "error")
                (ev / "error_dynamic.txt").write_text(traceback.format_exc(), encoding="utf-8")
            else:
                results.append(res)
                if res.tools_missing:
                    blockers.append(f"dynamic: fehlende/teilweise Tools: {', '.join(sorted(set(res.tools_missing)))}")
                hop("soldier:dynamic", res.skill, res.summary_de, res.warum, res.fund, res.next, res.status)
                snapshot("dynamic", active="dynamic", c=c, route=route)
        elif gate.dynamic == "ask":
            from ..soldiers import dynamic_lab as _dyn
            br = _dyn.blocked_result(gate.notes_de[0] if gate.notes_de else "Oversight fehlt")
            blockers.append("Dynamic BLOCKIERT: " + (gate.notes_de[0] if gate.notes_de else "kein Oversight"))
            hop("soldier:dynamic", br.skill, br.summary_de, br.warum, br.fund, br.next, "blocked")
            # Evidence-Marker
            (ev / "dynamic_blocked.txt").write_text(br.fund + "\n", encoding="utf-8")
            snapshot("static", c=c, route=route)
        # Phase 4 – Merge
        snapshot("merge", active="merge", c=c, route=route)
        n3 = _next3_strings(route, results)
        case_row = {**snap_case, "kind": c["kind"], "subtype": c["subtype"]}
        reports.write_dossier(case_dir, case_row, c, route, results, n3, GATE_TEXT_DE.split(". ") + gate.notes_de)
        hop("merge", "re-result-dossier",
            "Merge: Dossier und Ledger geschrieben, Brain aktualisiert.",
            "Die Queen führt alle Soldaten-Ergebnisse zu einem Dossier mit Erklärung und einem Ledger mit Next-3 zusammen – damit die nächste Session sofort weitermacht.",
            f"{len(results)} Soldat(en) fertig, {len(blockers)} Hinweis(e)/Blocker. Dossier und Ledger liegen in cases/{case_id}/.", n3)
        reports.write_ledger(case_dir, case_row, route, hops, blockers, n3, gate.notes_de)
        snapshot("idle", c=c, route=route, finished=True, next3=n3)
        db.update_case(case_id, status="done")
        db.add_event(case_id, "done", "Lauf abgeschlossen")
        with _NOTES_LOCK:
            config.NOTES_DIR.mkdir(parents=True, exist_ok=True)
            led = config.NOTES_DIR / "LEDGER.md"
            if not led.exists():
                led.write_text("---\nqueen_id: yellow\ntype: global-ledger\n---\n# Yellow Queen – globales Ledger\n\n", encoding="utf-8")
            with open(led, "a", encoding="utf-8") as f:
                f.write(f"- {config.now_iso()} · `{case_id}` · {c['kind']} · Route {route.id} · sha256 `{c['sha256'][:16]}`\n")
    except Exception as e:  # noqa: BLE001
        blockers.append(f"Queen-Fehler: {type(e).__name__}: {e}")
        db.update_case(case_id, status="error")
        db.add_event(case_id, "error", f"{type(e).__name__}: {e}")
        snapshot("idle", finished=True)
    return db.get_case(case_id) or {}
