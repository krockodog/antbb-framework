"""Real soldier/status feed for Hub /api/queens (no mock names)."""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger("allone.real_queens")

BACKUP = Path(os.environ.get("ANTBB_COLONY_ROOT", "/home/lordix/antbb.before-all-and-one"))
YQ = Path(os.environ.get("YELLOW_QUEEN_ROOT", os.environ.get("YQ_HOME", "/home/lordix/yellow-queen")))


def _ensure_colony_path() -> None:
    root = str(BACKUP.resolve())
    if root not in sys.path:
        sys.path.insert(0, root)


def _registry_soldiers(include_blue: bool = True) -> list[dict]:
    _ensure_colony_path()
    try:
        from antbb.registry import build_registry  # type: ignore

        reg = build_registry(include_blue=include_blue)
        return list(reg.get("soldiers") or [])
    except Exception as exc:  # noqa: BLE001
        log.warning("build_registry failed: %s", exc)
        return []


def _red_soldiers() -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for s in _registry_soldiers(include_blue=True):
        if s.get("colony") == "blue":
            continue
        n = s.get("name") or s.get("specialty")
        if not n or str(n).startswith("blue-"):
            continue
        n = str(n)
        if n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out


def _blue_soldiers() -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for s in _registry_soldiers(include_blue=True):
        n = s.get("name") or s.get("specialty")
        if not n:
            continue
        n = str(n)
        if s.get("colony") == "blue" or n.startswith("blue-"):
            if n not in seen:
                seen.add(n)
                out.append(n)
    if out:
        return out
    _ensure_colony_path()
    try:
        from antbb.agents.blue import BLUE_AGENTS  # type: ignore

        for a in BLUE_AGENTS:
            n = (
                a.get("name")
                if isinstance(a, dict)
                else (getattr(a, "name", None) or getattr(a, "specialty", None))
            )
            if n and str(n) not in seen:
                seen.add(str(n))
                out.append(str(n))
    except Exception as exc:  # noqa: BLE001
        log.warning("BLUE_AGENTS: %s", exc)
    return out


def _yellow_soldiers() -> list[str]:
    root = str(YQ.resolve())
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        from yellow_queen.soldiers import REGISTRY  # type: ignore

        return sorted(REGISTRY.keys())
    except Exception as exc:  # noqa: BLE001
        log.warning("yellow REGISTRY: %s", exc)
        return ["triage", "pe", "dotnet", "android", "elf", "hex", "dos", "dynamic"]


def real_soldier_ids(queen_id: str) -> list[str] | None:
    """Echte Soldier-IDs aus der antbb-Registry.

    Gibt None zurück, wenn die Registry nicht importierbar ist oder leer
    liefert — der Aufrufer fällt dann auf den Seed-Katalog zurück.
    """
    try:
        if queen_id == "red":
            ids = _red_soldiers()
        elif queen_id == "blue":
            ids = _blue_soldiers()
        else:
            return None
    except Exception as exc:  # noqa: BLE001
        log.warning("real_soldier_ids(%s): %s", queen_id, exc)
        return None
    return ids or None


def _case_count() -> int | None:
    try:
        cases = Path(os.environ.get("YQ_CASES_DIR") or (YQ / "cases"))
        if cases.is_dir():
            return sum(1 for p in cases.iterdir() if p.is_dir())
    except Exception:
        return None
    return None


def _live_status(queen_id: str, soldier_ids: list[str]) -> str:
    n = len(soldier_ids)
    if queen_id == "red":
        return f"Kolonie bereit · {n} Soldaten (echt) · Scope default-deny."
    if queen_id == "blue":
        return f"Verteidigung bereit · {n} Blue-Soldaten (echt) · Fixes nur mit Oversight."
    if queen_id == "yellow":
        c = _case_count()
        if c is None:
            return f"RE bereit · {n} Soldaten (echt)."
        return f"RE bereit · {n} Soldaten (echt) · {c} Fälle."
    return f"{n} Soldaten."


def enrich_summary(summary: dict[str, Any]) -> dict[str, Any]:
    q = summary.get("queen_id")
    if q == "red":
        ids = _red_soldiers()
    elif q == "blue":
        ids = _blue_soldiers()
    elif q == "yellow":
        ids = _yellow_soldiers()
    else:
        return summary
    summary = dict(summary)
    if not ids:
        summary["soldier_ids"] = []
        summary["live_satz"] = "Keine echten Soldaten geladen."
        return summary
    existing = {item.get("soldier_id"): item for item in summary.get("soldiers") or []}
    summary["soldiers"] = []
    for soldier_id in ids:
        item = dict(existing.get(soldier_id) or {})
        item.update({
            "queen_id": q,
            "soldier_id": soldier_id,
            "name": soldier_id,
            "role": item.get("role") or "Echter Colony-Soldat",
            "mode": item.get("mode") or "wacht",
            "tut": item.get("tut") or "Bereit",
            "live_satz": item.get("live_satz") or "Aus der echten Colony-Registry geladen.",
            "playbook_ids": list(item.get("playbook_ids") or []),
            "playbooks": list(item.get("playbooks") or []),
            "oversight_required": True,
            "stub": False,
            "stub_note": "echt",
        })
        summary["soldiers"].append(item)
    summary["soldier_ids"] = ids[:10]
    summary["soldier_count"] = len(ids)
    summary["live_satz"] = _live_status(q, ids)
    sm = summary.get("summary") or ""
    for bad in ("Mocks", "Mock", "Import-Mock", "geplant/Mock"):
        sm = sm.replace(bad, "Colony")
    summary["summary"] = sm
    return summary
