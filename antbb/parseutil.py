"""Kompatibilitäts-Schicht für das robuste JSON-Parsing.

Die eigentliche Logik lebt zentral in :mod:`antbb.tools.parsers`
(``safe_parse_json`` mit ``parse_status``/``parse_warning``, ABPM-12).
Diese Datei hält nur die bisherige Tupel-API ``(obj, warning)`` für ältere
Aufrufer (remediation, agents.analysis) stabil – ohne stille ``except``-Blöcke.
"""
from __future__ import annotations

from typing import Any, Optional

from .tools.parsers import (
    PARSE_EMPTY, PARSE_OK, METHOD_EMBEDDED, METHOD_LINES, safe_parse_json,
)


def parse_json_robust(
    text: Any,
    *,
    expect: type | tuple[type, ...] = (dict, list),
    context: str = "",
) -> tuple[Optional[Any], Optional[str]]:
    """Parst JSON robust; Rückgabe ``(obj, warning)`` wie bisher.

    * sauber + erwarteter Typ   -> ``(obj, None)``
    * leer                      -> ``(None, "empty_output")``
    * Fallback gegriffen        -> ``(daten, parse_warning)``; bei reiner
      Zeilen-Extraktion ist ``daten`` ein dict mit ``parse_warning: True``,
      ``raw_excerpt``, ``lines``, ``kv_guess`` (Markierung für Altaufrufer).
    """
    res = safe_parse_json(text, context, expect=expect)
    if res.parse_status == PARSE_EMPTY:
        return None, "empty_output"
    if res.parse_status == PARSE_OK:
        return res.data, None
    data = res.data
    if res.method == METHOD_LINES and isinstance(data, dict):
        data = {"parse_warning": True, **data}
    elif res.method == METHOD_EMBEDDED and isinstance(data, list):
        types = expect if isinstance(expect, tuple) else (expect,)
        if list not in types:
            # Mehrere eingebettete Werte, Aufrufer erwartet aber kein Array:
            # den ersten Wert vom erwarteten Typ nehmen (Warnung bleibt).
            data = next((v for v in data if isinstance(v, types)), data)
    return data, res.parse_warning


def attach_parse_warning(result: dict, warning: Optional[str]) -> dict:
    """Hängt parse_warning an ein Ergebnis-dict (idempotent)."""
    if warning:
        result = dict(result)
        result["parse_warning"] = warning
    return result
