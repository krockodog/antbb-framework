"""Robustes JSON-/Zeilen-Parsing ohne stille leere catch-Blöcke.

Tool-Runner (kali, greenbone, …) bleiben Source of Truth. Bei JSON-Parse-
Fehlern wird ein strukturierter Fallback geliefert (Regex-/Zeilen-Extraktion)
plus ``parse_warning``, damit echte Tool-Ausgaben nicht verloren gehen.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional


def parse_json_robust(
    text: str,
    *,
    expect: type | tuple[type, ...] = (dict, list),
) -> tuple[Optional[Any], Optional[str]]:
    """Parst JSON; bei Fehler: (None, warning) und optionaler Zeilen-Fallback.

    Returns:
        (obj, None) bei Erfolg.
        (fallback_obj_or_None, warning) bei Fehler — fallback_obj ist ein
        dict mit ``raw_excerpt`` / ``lines`` / ``kv_guess``, nie erfunden.
    """
    raw = text if isinstance(text, str) else (text.decode("utf-8", "replace") if isinstance(text, (bytes, bytearray)) else str(text or ""))
    raw_stripped = raw.strip()
    if not raw_stripped:
        return None, "empty_output"
    try:
        obj = json.loads(raw_stripped)
    except json.JSONDecodeError as exc:
        # Manche Tools (nuclei NDJSON, sqlmap) liefern NDJSON oder Präambel+JSON.
        nd = _try_ndjson(raw_stripped)
        if nd is not None:
            return nd, f"ndjson_fallback:{exc}"
        # Erste {...} oder [...] Klammerung herausziehen
        extracted = _extract_json_blob(raw_stripped)
        if extracted is not None:
            try:
                obj = json.loads(extracted)
                if isinstance(obj, expect):
                    return obj, f"blob_extract:{exc}"
            except json.JSONDecodeError:
                pass
        fallback = _line_fallback(raw_stripped)
        return fallback, f"json_decode:{exc}"
    except Exception as exc:  # unerwartete Typen
        return _line_fallback(raw_stripped), f"parse_error:{type(exc).__name__}:{exc}"
    if not isinstance(obj, expect):
        return obj, f"unexpected_type:{type(obj).__name__}"
    return obj, None


def _try_ndjson(text: str) -> Optional[list]:
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not (line.startswith("{") or line.startswith("[")):
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items or None


def _extract_json_blob(text: str) -> Optional[str]:
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start >= 0 and end > start:
            return text[start : end + 1]
    return None


_KV_RE = re.compile(
    r"^(?P<k>[A-Za-z_][\w.\-]{0,80})\s*[:=]\s*(?P<v>.{1,400})$"
)


def _line_fallback(text: str) -> dict:
    """Strukturierter Fallback: Roh-Auszug + Key=Value-Zeilen + alle Zeilen."""
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    kv: dict[str, str] = {}
    for ln in lines[:200]:
        m = _KV_RE.match(ln.strip())
        if m and m.group("k") not in kv:
            kv[m.group("k")] = m.group("v").strip().strip("\",'")
    return {
        "parse_warning": True,
        "raw_excerpt": text[:4000],
        "lines": lines[:200],
        "kv_guess": kv,
    }


def attach_parse_warning(result: dict, warning: Optional[str]) -> dict:
    """Hängt parse_warning an ein Ergebnis-dict (idempotent)."""
    if warning:
        result = dict(result)
        result["parse_warning"] = warning
    return result
