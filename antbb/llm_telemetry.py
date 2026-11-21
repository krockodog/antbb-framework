"""Explizite LLM-Telemetrie pro Run (used / fallback_no_llm / disabled_by_policy / error).

Kein Secret, nur Status + Modellname. Wird in run_history.llm_status /
run_history.llm_model und optional in scan_runs.meta persistiert.
"""
from __future__ import annotations

from typing import Any, Optional

# Erlaubte Status-Werte (Single Source of Truth)
LLM_USED = "used"
LLM_FALLBACK = "fallback_no_llm"
LLM_DISABLED = "disabled_by_policy"
LLM_ERROR = "error"
LLM_UNKNOWN = ""

ALLOWED = frozenset({LLM_USED, LLM_FALLBACK, LLM_DISABLED, LLM_ERROR, LLM_UNKNOWN})


def classify(*, use_llm_requested: bool, llm_client: Any = None,
             error: Optional[str] = None, disabled_by_policy: bool = False) -> dict:
    """Leitet llm_status + llm_model aus dem realen Laufzustand ab."""
    model = ""
    provider = ""
    try:
        from . import llm as llm_mod
        model = getattr(llm_mod, "MAIN_MODEL", "") or ""
    except Exception:
        pass
    if llm_client is not None:
        try:
            cfg = getattr(llm_client, "cfg", None)
            if cfg is not None:
                provider = getattr(cfg, "name", "") or ""
                model = getattr(cfg, "model", None) or model
        except Exception:
            pass
        try:
            # Manche Clients halten das Modell separat
            model = getattr(llm_client, "model", None) or model
        except Exception:
            pass
    if disabled_by_policy or (not use_llm_requested):
        return {"llm_status": LLM_DISABLED, "llm_model": model or "",
                "llm_provider": provider, "llm_error": ""}
    if error:
        return {"llm_status": LLM_ERROR, "llm_model": model or "",
                "llm_provider": provider, "llm_error": str(error)[:400]}
    if llm_client is None:
        return {"llm_status": LLM_FALLBACK, "llm_model": model or "",
                "llm_provider": provider, "llm_error": ""}
    configured = bool(getattr(llm_client, "configured", True))
    if not configured:
        return {"llm_status": LLM_FALLBACK, "llm_model": model or "",
                "llm_provider": provider, "llm_error": ""}
    return {"llm_status": LLM_USED, "llm_model": model or "",
            "llm_provider": provider, "llm_error": ""}


def as_meta(tele: dict) -> dict:
    """Für scan_runs.meta / Evidence — ohne Secrets."""
    return {
        "llm_status": tele.get("llm_status") or "",
        "llm_model": tele.get("llm_model") or "",
        "llm_provider": tele.get("llm_provider") or "",
        "llm_error": tele.get("llm_error") or "",
    }
