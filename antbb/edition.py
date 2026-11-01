"""Plattform-Edition: free | plan.

Setzt install-and-start.sh / ./run.sh über ANTBB_EDITION in antbb.env.
  * free  – API-Key, Ollama oder ohne KI (Default)
  * plan  – nach OAuth-Identifikation (Menü [3]); erweiterte Features

Keine Secrets hier. Feature-Flags sind ehrlich und lokal prüfbar.
"""
from __future__ import annotations

import os
from typing import Any

_TRUE = {"1", "true", "yes", "on"}

# Features, die NUR in der Plan-Edition freigeschaltet sind.
PLAN_ONLY: frozenset[str] = frozenset({
    "oauth_identity",
    "extended_orchestration",
    "plan_status_badge",
})


def edition() -> str:
    raw = (os.environ.get("ANTBB_EDITION") or "free").strip().lower()
    return raw if raw in ("free", "plan") else "free"


def is_plan() -> bool:
    return edition() == "plan"


def ai_mode() -> str:
    return (os.environ.get("ANTBB_AI_MODE") or "none").strip().lower() or "none"


def has_feature(name: str) -> bool:
    """True, wenn das Feature in der aktuellen Edition erlaubt ist."""
    if name in PLAN_ONLY:
        return is_plan()
    return True


def status() -> dict[str, Any]:
    """Öffentlicher Status ohne Secrets."""
    ed = edition()
    return {
        "edition": ed,
        "ai_mode": ai_mode(),
        "is_plan": ed == "plan",
        "oauth_provider": (os.environ.get("ANTBB_OAUTH_PROVIDER") or "").strip() or None,
        "plan_features": sorted(PLAN_ONLY) if ed == "plan" else [],
        "note": (
            "OAuth-Login → Plan-Version mit erweiterten Features."
            if ed == "plan"
            else "Free-Version (API-Key / Ollama / ohne KI)."
        ),
    }
