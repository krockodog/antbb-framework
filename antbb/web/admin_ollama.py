"""Admin-Seite fuer den lokalen Ollama-Dienst (/admin/ollama).

* Nur Rolle admin (webguard._ADMIN_ONLY greift fuer /admin/* und /api/admin/*,
  zusaetzlich hier serverseitig geprueft).
* Ollama bleibt auf 127.0.0.1:11434. Kein Proxy nach aussen: der Browser
  spricht nur mit diesen Admin-Endpunkten, nie direkt mit Ollama.
* Modellwechsel nur zwischen INSTALLIERTEN Modellen. Die Wahl liegt als
  Setting ``llm.ollama_model`` in der DB (Fallback: ANTBB_MAIN_MODEL/
  ANTBB_FAST_MODEL aus der Umgebung) und wirkt sofort, ohne Neustart.
* Kein Pull, kein Loeschen von Modellen.
"""
from __future__ import annotations

import dataclasses
import logging
import os
import time
from typing import Any, Callable, Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .. import webauth

log = logging.getLogger("antbb.admin")
SETTING_KEY = "llm.ollama_model"
_TIMEOUT = 4.0


def _base_url() -> str:
    url = os.environ.get("OLLAMA_BASE_URL", "").strip()
    if not url:
        try:
            from .. import llm
            url = llm.PROVIDERS["ollama"].base_url
        except Exception:  # noqa: BLE001
            url = "http://127.0.0.1:11434"
    return url.rstrip("/")


def _require_admin(request: Request) -> dict:
    user = getattr(request.state, "user", None) or {}
    if not webauth.is_admin(user.get("role")):
        raise HTTPException(403, "Only an admin may run this action.")
    return user


def _get(path: str) -> tuple[Optional[dict], str]:
    import httpx
    try:
        r = httpx.get(_base_url() + path, timeout=_TIMEOUT)
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        return r.json(), ""
    except Exception as exc:  # noqa: BLE001
        return None, type(exc).__name__


def _post(path: str, payload: dict, timeout: float = 120.0) -> tuple[Optional[dict], str]:
    import httpx
    try:
        r = httpx.post(_base_url() + path, json=payload, timeout=timeout)
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        return r.json(), ""
    except Exception as exc:  # noqa: BLE001
        return None, type(exc).__name__


def _host_stats() -> dict:
    """Host-RAM/Load aus /proc (network_mode host, /proc/meminfo zeigt den Host).
    Den ollama-Prozess (RSS) sieht der Container nicht (kein pid: host)."""
    out: dict[str, Any] = {}
    try:
        mem = {}
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                k, v = line.split(":", 1)
                mem[k] = int(v.strip().split()[0]) * 1024
        out["mem_total"] = mem.get("MemTotal")
        out["mem_available"] = mem.get("MemAvailable")
    except Exception:  # noqa: BLE001
        pass
    try:
        with open("/proc/loadavg", encoding="ascii") as fh:
            out["load"] = [float(x) for x in fh.read().split()[:3]]
        out["cpus"] = os.cpu_count()
    except Exception:  # noqa: BLE001
        pass
    return out


def current_model(store) -> dict:
    from .. import llm
    saved = ""
    try:
        saved = store.get_setting(SETTING_KEY, "") or ""
    except Exception:  # noqa: BLE001
        saved = ""
    env_main = os.environ.get("ANTBB_MAIN_MODEL", "").strip()
    env_fast = os.environ.get("ANTBB_FAST_MODEL", "").strip()
    p = llm.PROVIDERS.get("ollama")
    return {
        "saved": saved,
        "source": "setting" if saved else ("env" if (env_main or env_fast) else "config"),
        "main_model": llm.MAIN_MODEL,
        "fast_model": llm.FAST_MODEL,
        "default_provider": llm.DEFAULT_PROVIDER,
        "ollama_provider_model": p.default_model if p else "",
        "env_main": env_main, "env_fast": env_fast,
    }


def apply_model(name: str) -> None:
    """Setzt das Modell zur Laufzeit (Haupt-/Flash-Modell + Ollama-Provider)."""
    from .. import llm
    if not name:
        return
    llm.MAIN_MODEL = name
    llm.FAST_MODEL = name
    p = llm.PROVIDERS.get("ollama")
    if p is not None:
        llm.PROVIDERS["ollama"] = dataclasses.replace(p, default_model=name, fast_model=name)


def _fmt_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "–"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return "–"


def status(store) -> dict:
    version, err = _get("/api/version")
    tags, _ = _get("/api/tags") if version else (None, "")
    ps, _ = _get("/api/ps") if version else (None, "")
    models = []
    for m in (tags or {}).get("models", []) or []:
        d = m.get("details") or {}
        models.append({"name": m.get("name") or m.get("model"), "size": m.get("size"),
                       "size_h": _fmt_bytes(m.get("size")),
                       "parameters": d.get("parameter_size", ""),
                       "quantization": d.get("quantization_level", ""),
                       "family": d.get("family", ""), "modified_at": m.get("modified_at", "")})
    loaded = []
    for m in (ps or {}).get("models", []) or []:
        loaded.append({"name": m.get("name") or m.get("model"), "size": m.get("size"),
                       "size_h": _fmt_bytes(m.get("size")),
                       "size_vram": m.get("size_vram"), "size_vram_h": _fmt_bytes(m.get("size_vram")),
                       "expires_at": m.get("expires_at", "")})
    host = _host_stats()
    host["mem_total_h"] = _fmt_bytes(host.get("mem_total"))
    host["mem_available_h"] = _fmt_bytes(host.get("mem_available"))
    return {"reachable": bool(version), "version": (version or {}).get("version", ""),
            "error": err if not version else "", "models": models, "loaded": loaded,
            "active": current_model(store), "host": host,
            "process_note": "RSS des ollama-Prozesses ist im Container nicht sichtbar "
                            "(kein pid: host). Speicher der geladenen Modelle siehe /api/ps."}


def register(app: FastAPI, templates, store_getter: Callable[[], Any]) -> None:
    # Gespeicherte Wahl beim Start anwenden (wirkt fuer alle KI-Aufrufe).
    try:
        saved = store_getter().get_setting(SETTING_KEY, "")
        if saved:
            apply_model(saved)
    except Exception:  # noqa: BLE001
        pass

    def _audit(request: Request, kind: str, detail: str) -> None:
        try:
            from .activity import record
            record(store_getter(), request, kind, detail=detail)
        except Exception:  # noqa: BLE001
            pass
        log.info("audit %s by=%s %s", kind, (getattr(request.state, "user", None) or {}).get("username"), detail)

    def _installed() -> list[str]:
        tags, _ = _get("/api/tags")
        return [m.get("name") or m.get("model") for m in (tags or {}).get("models", []) or []]

    @app.get("/admin/ollama", response_class=HTMLResponse, include_in_schema=False)
    def admin_ollama(request: Request, message: str = "", error: str = ""):
        _require_admin(request)
        return templates.TemplateResponse(request, "admin_ollama.html", {
            "st": status(store_getter()), "message": message[:300], "error": error[:300]})

    @app.get("/api/admin/ollama", include_in_schema=False)
    def api_ollama(request: Request):
        _require_admin(request)
        return status(store_getter())

    def _choose(request: Request, model: str):
        model = (model or "").strip()
        installed = _installed()
        if model not in installed:
            return None, "Modell ist nicht installiert."
        store = store_getter()
        before = current_model(store)["main_model"]
        store.set_setting(SETTING_KEY, model)
        apply_model(model)
        _audit(request, "ollama_model_changed", f"{before} -> {model}")
        return model, ""

    @app.post("/admin/ollama/model", include_in_schema=False)
    def admin_ollama_model(request: Request, model: str = Form("")):
        _require_admin(request)
        ok, err = _choose(request, model)
        from urllib.parse import quote
        if err:
            return RedirectResponse("/admin/ollama?error=" + quote(err), status_code=303)
        return RedirectResponse("/admin/ollama?message=" + quote(f"Modell {ok} ist jetzt aktiv."), status_code=303)

    @app.post("/api/admin/ollama/model", include_in_schema=False)
    async def api_ollama_model(request: Request):
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        ok, err = _choose(request, str((body or {}).get("model") or ""))
        if err:
            return JSONResponse({"error": err}, status_code=400)
        return {"ok": True, "model": ok}

    def _keep(request: Request, model: str, keep_alive):
        model = (model or "").strip()
        if model not in _installed():
            return "Modell ist nicht installiert."
        _res, err = _post("/api/generate", {"model": model, "prompt": "", "keep_alive": keep_alive,
                                            "stream": False}, timeout=180.0)
        _audit(request, "ollama_load" if keep_alive else "ollama_unload", model + (f" ({err})" if err else ""))
        return f"Ollama: {err}" if err else ""

    @app.post("/admin/ollama/load", include_in_schema=False)
    def admin_ollama_load(request: Request, model: str = Form("")):
        _require_admin(request)
        from urllib.parse import quote
        err = _keep(request, model, "10m")
        if err:
            return RedirectResponse("/admin/ollama?error=" + quote(err), status_code=303)
        return RedirectResponse("/admin/ollama?message=" + quote(f"{model} geladen (10 min)."), status_code=303)

    @app.post("/admin/ollama/unload", include_in_schema=False)
    def admin_ollama_unload(request: Request, model: str = Form("")):
        _require_admin(request)
        from urllib.parse import quote
        err = _keep(request, model, 0)
        if err:
            return RedirectResponse("/admin/ollama?error=" + quote(err), status_code=303)
        return RedirectResponse("/admin/ollama?message=" + quote(f"{model} entladen."), status_code=303)
