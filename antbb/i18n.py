"""One catalog for the web UI. German is the default; English is complete.

Resolution order: explicit ``?lang=`` → ``antbb_lang`` cookie → ``Accept-Language`` → ``de``.
An unknown tag is ignored and the next source is tried, so ``?lang=zz`` falls back to German.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Mapping, Optional
from urllib.parse import urlencode

import contextvars

COOKIE = "antbb_lang"
COOKIE_MAX_AGE = 60 * 60 * 24 * 365
SUPPORTED = ("de", "en")
DEFAULT = "de"

_LOCALE = Path(__file__).resolve().parent / "locale"
_CATALOGS: dict[str, dict[str, str]] = {
    code: json.loads((_LOCALE / f"{code}.json").read_text(encoding="utf-8"))
    for code in SUPPORTED
}
_LANG: contextvars.ContextVar[str] = contextvars.ContextVar("antbb_lang", default=DEFAULT)
_REQUEST: contextvars.ContextVar[object | None] = contextvars.ContextVar("antbb_request", default=None)


def catalogs() -> Mapping[str, Mapping[str, str]]:
    return _CATALOGS


def normalize(value: Optional[str]) -> Optional[str]:
    """Return ``de`` or ``en`` when the tag is one of those languages, else None."""
    if not value:
        return None
    tag = value.strip().lower().replace("_", "-")
    if tag in SUPPORTED:
        return tag
    primary = tag.split("-", 1)[0]
    if primary in SUPPORTED:
        return primary
    return None


def resolve_lang(
    explicit: Optional[str] = None,
    cookie: Optional[str] = None,
    accept_language: Optional[str] = None,
) -> str:
    """``?lang`` wins, then the cookie, then the first supported Accept-Language tag."""
    chosen = normalize(explicit)
    if chosen:
        return chosen
    chosen = normalize(cookie)
    if chosen:
        return chosen
    if accept_language:
        for part in accept_language.split(","):
            chosen = normalize(part.split(";", 1)[0])
            if chosen:
                return chosen
    return DEFAULT


def t(key: str, lang: Optional[str] = None, **variables: object) -> str:
    """Look up ``key`` in the active (or given) language. Missing keys return the key."""
    code = normalize(lang) or _LANG.get() or DEFAULT
    text = _CATALOGS.get(code, {}).get(key)
    if text is None:
        text = _CATALOGS[DEFAULT].get(key, key)
    if variables:
        try:
            return text.format(**variables)
        except (KeyError, IndexError, ValueError):
            return text
    return text


def current_lang() -> str:
    return _LANG.get()


def catalog_for(lang: Optional[str] = None) -> dict[str, str]:
    code = normalize(lang) or _LANG.get() or DEFAULT
    return dict(_CATALOGS.get(code, _CATALOGS[DEFAULT]))


def activate(lang: str) -> str:
    code = normalize(lang) or DEFAULT
    _LANG.set(code)
    return code


def activate_request(request) -> str:
    """Resolve the language for this request and remember the request for link building."""
    _REQUEST.set(request)
    explicit = request.query_params.get("lang") if request is not None else None
    cookie = request.cookies.get(COOKIE) if request is not None else None
    accept = request.headers.get("accept-language") if request is not None else None
    return activate(resolve_lang(explicit, cookie, accept))


def lang_href(lang: str) -> str:
    """Current path and query, with ``lang`` replaced. Other parameters stay."""
    request = _REQUEST.get()
    code = normalize(lang) or DEFAULT
    if request is None:
        return f"/?lang={code}"
    pairs = [(k, v) for k, v in request.query_params.multi_items() if k != "lang"]
    pairs.append(("lang", code))
    return f"{request.url.path}?{urlencode(pairs)}"


def stamp_lang_cookie(response, request):
    """Persist ``?lang=`` for a year. The cookie is readable by the static hub."""
    explicit = normalize(request.query_params.get("lang")) if request is not None else None
    if not explicit:
        return response
    response.set_cookie(
        COOKIE,
        explicit,
        max_age=COOKIE_MAX_AGE,
        path="/",
        samesite="lax",
        httponly=False,
        secure=request.url.scheme == "https",
    )
    return response


_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def js_catalog(lang: Optional[str] = None) -> dict[str, str]:
    return catalog_for(lang)
