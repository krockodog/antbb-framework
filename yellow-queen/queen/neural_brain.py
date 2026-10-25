"""Yellow Neural Brain – Snapshot lesen/schreiben (Anzeige + Navigation).

Knoten für All-and-One unter http://192.168.2.7:1001/brain (kanonisch).
Interim /yellow/brain bleibt als Yellow Live-Status.
"""
from __future__ import annotations

import json
import threading
from typing import Any

from .. import config, db

_lock = threading.Lock()
LATEST_FILE = "brain_snapshot.json"

PHASES_DE = {
    "idle": "Leerlauf", "triage": "Triage (Gate/Classify)", "static": "Statische Analyse",
    "reconstruct": "Rekonstruktion", "dynamic": "Dynamic (Lab, nur mit Oversight)", "merge": "Merge (Dossier/Ledger)",
}

CANONICAL_BRAIN = "http://192.168.2.7:1001/brain"


def idle_snapshot() -> dict[str, Any]:
    steps = [
        {"id": "n1", "idx": 1, "label": "Sample hochladen (eigen/Lab/freigegeben)", "status": "active", "progress": "1/3",
         "warum": "Ohne autorisiertes Sample darf Yellow nichts speichern oder analysieren.",
         "fund": "Noch kein Fall.", "next": ["Autorisierungs-Checkbox setzen"], "tool": "upload", "jetzt": True},
        {"id": "n2", "idx": 2, "label": "Classify + Routing abwarten", "status": "pending", "progress": "2/3",
         "warum": "Format entscheidet die Toolchain (PE/.NET/APK/ELF/HEX/DOS).",
         "fund": "–", "next": ["Packer/DIE → Ghidra → Dossier"], "tool": "classify", "jetzt": False},
        {"id": "n3", "idx": 3, "label": "Dossier und Ledger lesen", "status": "pending", "progress": "3/3",
         "warum": "Ergebnisse mit Adresse gehören ins Dossier, nicht nur in die Textliste.",
         "fund": "–", "next": ["Next-3 weiterverfolgen"], "tool": "dossier", "jetzt": False},
    ]
    return {
        "queen_id": "yellow", "brain": "yellow-neural-brain", "case_id": None, "sample_sha": None, "title": "Kein aktiver Fall",
        "phase": "idle", "phase_de": PHASES_DE["idle"], "active_soldier": None, "active_playbook": None, "finished": True, "dynamic": "no",
        "oversight": {"dynamic": "no", "oversight_confirmed": False},
        "hops": [],
        "erklaerbaer": {
            "warum": "Yellow Queen wartet auf ein Sample. Erst wenn du die Autorisierung bestätigst, darf ich überhaupt etwas speichern oder analysieren.",
            "fund": "Noch nichts analysiert. Das Gehirn zeigt hier später jeden Schritt (Hop): classify → toolchain → Soldat → merge – jeweils mit Erklärung.",
            "next": ["Auf der Startseite ein autorisiertes Sample hochladen", "Autorisierungs-Checkbox setzen (Pflicht)", "Dynamic nur mit Oversight: dann führt Yellow den Lab-Pfad selbst aus"],
        },
        "next3": [s["label"] for s in steps],
        "next3_steps": steps,
        "active_step": steps[0],
        "findings": [],
        "bypass": {
            "id": "bypass", "label": "Bypass (nach Classify)", "status": "pending",
            "playbook": "none", "requires_oversight": False,
            "warum": "Ob ein Packer-Bypass nötig ist, wissen wir erst nach Classify/DIE.",
            "fund": "Noch kein Sample.", "next": ["Sample hochladen"], "hints": [],
        },
        "dynamic_step": {
            "id": "dynamic", "label": "Dynamic-Lab (nur mit Oversight)", "status": "pending",
            "playbook": "dynamic-lab / frida-lab", "requires_oversight": True,
            "warum": "Mit Oversight startet Yellow den Lab-Pfad selbst – kein bloßes Vormerken.",
            "fund": "Noch kein Sample / kein Oversight.", "next": ["Dynamic+Oversight setzen"], "tools_used": [],
        },
        "last_ran_at": None,
        "dossier_path": None, "ledger_path": None,
        "links": {"canonical_brain": CANONICAL_BRAIN},
        "blockers": [],
        "updated_at": config.now_iso(),
    }



def _ensure_ui_fields(snap: dict[str, Any]) -> dict[str, Any]:
    """Alte Snapshots um Next-3/Findings/Bypass/Dynamic ergänzen (Mount-freundlich)."""
    idle = idle_snapshot()
    for k in ("next3_steps", "findings", "bypass", "dynamic_step", "active_step", "last_ran_at"):
        if k not in snap or snap[k] is None:
            snap[k] = idle.get(k)
    if not snap.get("next3"):
        snap["next3"] = idle["next3"]
    links = snap.setdefault("links", {})
    links.setdefault("canonical_brain", CANONICAL_BRAIN)
    snap.setdefault("queen_id", "yellow")
    return snap


def write_snapshot(case_id: str, snap: dict[str, Any]) -> None:
    snap["queen_id"] = "yellow"
    snap["updated_at"] = config.now_iso()
    snap["phase_de"] = PHASES_DE.get(snap.get("phase", "idle"), snap.get("phase", ""))
    links = snap.setdefault("links", {})
    links.setdefault("canonical_brain", CANONICAL_BRAIN)
    with _lock:
        config.ensure_dirs()
        (config.DATA_DIR / LATEST_FILE).write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
        db.save_snapshot(case_id, snap)


def read_snapshot(case_id: str | None = None) -> dict[str, Any]:
    with _lock:
        if case_id:
            s = db.load_snapshot(case_id)
            if s:
                return _ensure_ui_fields(s)
            c = db.get_case(case_id)
            if c:  # Fall existiert, Lauf startet gerade
                base = idle_snapshot()
                base.update({
                    "case_id": case_id, "title": c["filename"], "phase": "triage", "phase_de": PHASES_DE["triage"],
                    "finished": False, "next3": ["Gate/Classify abwarten", "Toolchain wählen", "Dossier schreiben"],
                    "erklaerbaer": {"warum": "Der Lauf wurde gerade angelegt.", "fund": "Noch kein Hop fertig.",
                                    "next": ["Kurz warten – die Anzeige aktualisiert sich selbst."]},
                })
                return base
            return idle_snapshot() | {"title": f"Fall {case_id} nicht gefunden"}
        f = config.DATA_DIR / LATEST_FILE
        if f.exists():
            try:
                return _ensure_ui_fields(json.loads(f.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass
    return idle_snapshot()
