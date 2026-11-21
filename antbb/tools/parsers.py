"""Safe-JSON-Parser mit ``parse_status`` und ``parse_warning`` (ABPM-12).

Zentraler Helfer für Tool-Ausgaben (kali-Adapter, Greenbone-Import, LLM-JSON).
Ziel: defektes oder nur teilweise lesbares JSON darf nie hinter einem stillen
``except`` als "ehrlich leer" verschwinden. Jeder gefangene Fehler erzeugt eine
``parse_warning``; das Ergebnis sagt immer, auf welchem Weg es zustande kam.

Drei Zustände (``parse_status``):

``"ok"``
    Der komplette Input ist sauberes JSON vom erwarteten Typ (bzw. bei JSONL:
    jede nicht-leere Zeile ist ein sauberes JSON-Objekt). ``parse_warning`` ist
    ``None``.
``"partial_fallback"``
    Der Input war nicht vollständig sauber, es wurde aber etwas Echtes
    herausgeholt: eingebettete JSON-Objekte/-Arrays (z. B. Banner + JSON,
    abgeschnittenes JSON mit vollständigen inneren Objekten) oder – wenn gar
    kein JSON zu retten ist – eine strukturierte Zeilen-/Feld-Extraktion.
    ``parse_warning`` ist IMMER gesetzt und nennt Kontext, Weg und Ursache.
``"empty"``
    Es gibt keine Daten. Normalfall: Input war ``None``, leer oder nur
    Whitespace -> ehrlich leer, ``parse_warning`` ist ``None``. Konnte der
    Input gar nicht gelesen werden (z. B. Datei-I/O-Fehler, siehe
    :func:`unreadable`), ist ``parse_warning`` mit der Ursache gesetzt.

Es werden keine Daten erfunden: ``data`` enthält nur, was wirklich im Input
steht (geparste JSON-Werte oder wörtliche Zeilen/Felder des Rohtexts).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional, Union

PARSE_OK = "ok"
PARSE_PARTIAL = "partial_fallback"
PARSE_EMPTY = "empty"

# Wege, auf denen ``data`` entstanden ist (für Logs/Diagnose).
METHOD_NONE = "none"
METHOD_JSON = "json"
METHOD_EMBEDDED = "embedded_json"
METHOD_JSONL = "jsonl"
METHOD_LINES = "line_fallback"

#: Obergrenzen gegen Ausreißer (sehr große/kaputte Ausgaben).
MAX_SCAN_CHARS = 8 * 1024 * 1024
MAX_EMBEDDED_VALUES = 10_000
MAX_FALLBACK_LINES = 200
MAX_EXCERPT_CHARS = 4000
MAX_WARNING_CHARS = 500

RawInput = Union[str, bytes, bytearray, None]

_KV_RE = re.compile(r"^(?P<k>[A-Za-z_][\w.\-]{0,80})\s*[:=]\s*(?P<v>.{1,400})$")


@dataclass
class ParseResult:
    """Einheitliches Ergebnis aller Parser in diesem Modul."""

    data: Any = None
    parse_status: str = PARSE_EMPTY
    parse_warning: Optional[str] = None
    context: str = ""
    method: str = METHOD_NONE
    #: Nur bei JSONL: Anzahl kaputter JSON-Zeilen bzw. ignorierter Textzeilen.
    stats: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.parse_status == PARSE_OK

    @property
    def is_line_fallback(self) -> bool:
        return self.method == METHOD_LINES

    def as_meta(self) -> dict:
        """Kompakte, JSON-taugliche Metadaten für Logs/Evidence/Reports."""
        meta = {"parse_status": self.parse_status, "parse_method": self.method}
        if self.context:
            meta["parse_context"] = self.context
        if self.parse_warning:
            meta["parse_warning"] = self.parse_warning
        return meta


# ---------------------------------------------------------------------------
# Öffentliche API
# ---------------------------------------------------------------------------
def safe_parse_json(raw: RawInput, context: str = "", *,
                    expect: Union[type, tuple] = (dict, list)) -> ParseResult:
    """Parst ``raw`` robust als JSON.

    Reihenfolge:
      1. ``None``/leer/Whitespace          -> ``empty``.
      2. sauberes ``json.loads`` + Typ passt -> ``ok``.
      3. Typ passt nicht (Schemabruch)      -> ``partial_fallback`` mit den Daten.
      4. Parsefehler: eingebettete JSON-Objekte/-Arrays suchen
         (``{...}`` / ``[...]``)            -> ``partial_fallback``;
         genau ein Fund -> ``data`` ist dieser Wert, mehrere -> Liste der Werte.
      5. nichts zu retten: Zeilen-/Feld-Extraktion -> ``partial_fallback`` mit
         ``data = {"raw_excerpt", "lines", "kv_guess"}``.
    """
    text, decode_note = _to_text(raw)
    stripped = text.strip()
    if not stripped:
        return _empty(None, context, decode_note)

    try:
        obj = json.loads(stripped)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        cause = f"json_decode: {_exc_text(exc)}"
    else:
        if isinstance(obj, expect):
            if decode_note:
                return _partial(obj, context, METHOD_JSON, decode_note)
            return ParseResult(data=obj, parse_status=PARSE_OK, context=context,
                               method=METHOD_JSON)
        return _partial(obj, context, METHOD_JSON,
                        _join(decode_note,
                              f"unexpected_type: {type(obj).__name__} "
                              f"(erwartet {_type_names(expect)})"))

    values, scan_note = extract_embedded_json(stripped)
    if values:
        data = values[0] if len(values) == 1 else values
        return _partial(data, context, METHOD_EMBEDDED,
                        _join(decode_note, cause,
                              f"{len(values)} eingebettete(s) JSON-Objekt(e)/-Array(s) gerettet",
                              scan_note))

    return _partial(line_fallback(stripped), context, METHOD_LINES,
                    _join(decode_note, cause, "kein JSON rettbar, Zeilen-/Feld-Extraktion",
                          scan_note))


def safe_parse_jsonl(raw: RawInput, context: str = "") -> ParseResult:
    """Parst zeilenweises JSON (NDJSON/JSONL, z. B. nuclei ``-jsonl``).

    ``data`` ist immer eine Liste der sauber geparsten Objekte/Arrays.
    Kaputte JSON-Zeilen werden NICHT zu Objekten umgedeutet (keine erfundenen
    Funde), sondern gezählt und in ``parse_warning`` benannt; Textzeilen ohne
    JSON (Banner/Logs) ebenso.
    """
    text, decode_note = _to_text(raw)
    if not text.strip():
        return _empty([], context, decode_note)

    items: list = []
    broken: list[str] = []
    text_lines = 0
    first_error = ""
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if not _looks_like_json_start(s):
            text_lines += 1       # Banner/Log, z. B. "[INF] ..." oder "[+] ..."
            continue
        try:
            items.append(json.loads(s))
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            broken.append(s[:120])
            if not first_error:
                first_error = _exc_text(exc)
    stats = {"items": len(items), "broken_json_lines": len(broken),
             "non_json_lines": text_lines}

    if not broken and not text_lines and not decode_note:
        return ParseResult(data=items, parse_status=PARSE_OK, context=context,
                           method=METHOD_JSONL, stats=stats)

    notes = [decode_note]
    if broken:
        notes.append(f"{len(broken)} kaputte JSON-Zeile(n) verworfen "
                     f"(erste: {first_error}; Auszug: {broken[0][:80]!r})")
    if text_lines:
        notes.append(f"{text_lines} Textzeile(n) ohne JSON ignoriert")
    res = _partial(items, context, METHOD_JSONL, _join(*notes))
    res.stats = stats
    return res


def extract_embedded_json(text: str) -> tuple[list, Optional[str]]:
    """Findet vollständige, eingebettete JSON-Werte (``{...}``/``[...]``).

    Läuft von links nach rechts; an jeder ``{``/``[``-Position wird ein
    JSON-Wert dekodiert. Gelingt es, wird der Wert übernommen und dahinter
    weitergesucht (innere Objekte eines bereits gefundenen Werts werden nicht
    doppelt gezählt). Bei abgeschnittenem JSON scheitert der äußere Wert, die
    vollständigen inneren Objekte werden aber gefunden.

    Skalare/leere Treffer (z. B. ``[]`` oder ``[1]`` aus Banner-Text) zählen
    nicht als gerettete Daten.

    Returns:
        (Werte, Hinweis) – Hinweis ist gesetzt, wenn eine Obergrenze griff.
    """
    note = None
    if len(text) > MAX_SCAN_CHARS:
        note = f"Suche auf die ersten {MAX_SCAN_CHARS} Zeichen begrenzt"
        text = text[:MAX_SCAN_CHARS]
    decoder = json.JSONDecoder()
    values: list = []
    i, n = 0, len(text)
    while i < n:
        j_obj = text.find("{", i)
        j_arr = text.find("[", i)
        cands = [j for j in (j_obj, j_arr) if j >= 0]
        if not cands:
            break
        j = min(cands)
        try:
            val, end = decoder.raw_decode(text, j)
        except (json.JSONDecodeError, RecursionError, ValueError):
            i = j + 1
            continue
        if _is_meaningful(val):
            values.append(val)
            if len(values) >= MAX_EMBEDDED_VALUES:
                note = _join(note, f"bei {MAX_EMBEDDED_VALUES} Werten abgebrochen")
                break
            i = end
        else:
            i = j + 1
    return values, note


def line_fallback(text: str) -> dict:
    """Strukturierte Zeilen-/Feld-Extraktion aus Rohtext (nichts erfunden)."""
    lines = [ln.rstrip() for ln in (text or "").splitlines() if ln.strip()]
    kv: dict[str, str] = {}
    for ln in lines[:MAX_FALLBACK_LINES]:
        m = _KV_RE.match(ln.strip())
        if m and m.group("k") not in kv:
            kv[m.group("k")] = m.group("v").strip().strip("\"',")
    return {
        "raw_excerpt": (text or "")[:MAX_EXCERPT_CHARS],
        "lines": lines[:MAX_FALLBACK_LINES],
        "line_count": len(lines),
        "kv_guess": kv,
    }


def unreadable(context: str, reason: str, *, empty_data: Any = None) -> ParseResult:
    """Ergebnis für Input, der gar nicht gelesen werden konnte (z. B. I/O).

    ``parse_status`` ist ``"empty"`` (keine Daten), aber ``parse_warning``
    nennt die Ursache – damit ist es vom ehrlich leeren Tool-Lauf unterscheidbar.
    """
    return _empty(empty_data, context, reason or "Input nicht lesbar")


# ---------------------------------------------------------------------------
# Interna
# ---------------------------------------------------------------------------
def _empty(data: Any, context: str, warning: Optional[str]) -> ParseResult:
    msg = None
    if warning:
        msg = f"{context}: {warning}" if context else warning
        msg = msg[:MAX_WARNING_CHARS]
    return ParseResult(data=data, parse_status=PARSE_EMPTY, parse_warning=msg,
                       context=context, method=METHOD_NONE)


def _to_text(raw: RawInput) -> tuple[str, Optional[str]]:
    if raw is None:
        return "", None
    if isinstance(raw, (bytes, bytearray)):
        b = bytes(raw)
        if b.startswith(b"\xef\xbb\xbf"):
            b = b[3:]
        try:
            return b.decode("utf-8"), None
        except UnicodeDecodeError as exc:
            return (b.decode("utf-8", "replace"),
                    f"utf8_decode: ungültige Bytes ersetzt ({_exc_text(exc)})")
    if isinstance(raw, str):
        return raw.lstrip("\ufeff"), None
    return str(raw), f"input_type: {type(raw).__name__} in Text umgewandelt"


_JSON_ARRAY_NEXT = set('{["-0123456789tfn]')


def _looks_like_json_start(line: str) -> bool:
    """``{...}`` immer; ``[...]`` nur, wenn danach ein JSON-typisches Zeichen folgt.

    So zählen Log-Präfixe wie ``[INF]``, ``[+]`` oder ``[WRN]`` als Textzeilen und
    nicht als kaputtes JSON.
    """
    if line.startswith("{"):
        return True
    if line.startswith("["):
        rest = line[1:].lstrip()
        return not rest or rest[0] in _JSON_ARRAY_NEXT
    return False


def _is_meaningful(val: Any) -> bool:
    if isinstance(val, dict):
        return bool(val)
    if isinstance(val, list):
        return any(isinstance(x, (dict, list)) for x in val)
    return False


def _partial(data: Any, context: str, method: str, warning: Optional[str]) -> ParseResult:
    msg = warning or "unbekannte Ursache"
    if context:
        msg = f"{context}: {msg}"
    if len(msg) > MAX_WARNING_CHARS:
        msg = msg[: MAX_WARNING_CHARS - 1] + "…"
    return ParseResult(data=data, parse_status=PARSE_PARTIAL, parse_warning=msg,
                       context=context, method=method)


def _join(*parts: Optional[str]) -> str:
    return "; ".join(p for p in parts if p)


def _exc_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:200]


def _type_names(expect: Union[type, tuple]) -> str:
    types = expect if isinstance(expect, tuple) else (expect,)
    return "|".join(t.__name__ for t in types)
