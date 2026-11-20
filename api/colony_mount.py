"""Mount REAL antbb colony (backup) into All-and-One on :1001.

Keeps hub/brain branding on All-and-One. Serves working Red/Blue UIs with
real scope, oversight, and scan paths from antbb.before-all-and-one.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from starlette.routing import Mount

log = logging.getLogger("allone.colony")

BACKUP_DEFAULT = "/home/lordix/antbb.before-all-and-one"

# Colony routes we want at the top level (absolute paths in templates).
# "/brain" wird bewusst VOM Kolonie-Gehirn bedient (eine Gehirn-Ansicht, siehe
# Brain-Entscheidung d08484e) – nicht mehr vom Hub-Shell-Export.
SKIP_EXACT = {
    "/",
    "/api/health",
    "/api/brain",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
    "/red",
    "/blue",
    "/yellow",
    "/yellow/brain",
    "/yellow/upload",
}

# /api/brain (exact) is the All-and-One hub payload and stays skipped.
# Literal colony routes such as /api/brain/nodes and /api/brain/logs must
# still be mounted — skipping the whole /api/brain/ prefix 404s the Knoten panel.
SKIP_PREFIXES = (
    "/yellow/",
    "/api/cases",
    "/api/classify",
    "/api/doctor",
)

# Explicit colony routes under /yellow/ that must stay on the antbb app
# (the prefix skip would otherwise hide them from the hosted API process).
YELLOW_COLONY_ALLOW = {
    "/yellow/report.pdf",
}


def _load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = val


def _dual_static(antbb_static: Path, yellow_static: Path):
    roots = [p for p in (antbb_static, yellow_static) if p.is_dir()]

    async def serve(full_path: str):
        rel = full_path.strip("/")
        if not rel or ".." in Path(rel).parts or rel.startswith("api"):
            return HTMLResponse("not found", status_code=404)
        for root in roots:
            candidate = (root / rel).resolve()
            try:
                if root.resolve() not in candidate.parents and candidate != root.resolve():
                    continue
            except OSError:
                continue
            if candidate.is_file():
                media = {
                    ".glb": "model/gltf-binary",
                    ".gltf": "model/gltf+json",
                    ".wasm": "application/wasm",
                    ".mjs": "application/javascript",
                    ".js": "application/javascript",
                }.get(candidate.suffix.lower())
                return FileResponse(candidate, media_type=media) if media else FileResponse(candidate)
        return HTMLResponse("not found", status_code=404)

    return serve


def attach_colony(app: FastAPI) -> dict[str, Any]:
    report: dict[str, Any] = {
        "ok": False,
        "backup": None,
        "added": [],
        "skipped": [],
        "error": None,
        "red": None,
        "blue": None,
    }
    backup = Path(os.environ.get("ANTBB_COLONY_ROOT", BACKUP_DEFAULT)).expanduser()
    report["backup"] = str(backup)
    if not backup.is_dir():
        report["error"] = f"colony backup missing: {backup}"
        log.warning(report["error"])
        return report

    # Prefer live secrets if present, else backup env.
    _load_env_file(Path("/home/lordix/antbb/antbb.env"))
    _load_env_file(backup / "antbb.env")
    # Shared All-and-One hub owns / and /brain — do not force blue-home redirects.
    os.environ["ANTBB_HOME"] = ""

    root = str(backup.resolve())
    if root not in sys.path:
        sys.path.insert(0, root)

    try:
        from antbb.web import app as colony_mod  # noqa: WPS433
        colony = colony_mod.app
    except Exception as exc:  # noqa: BLE001
        report["error"] = f"colony import failed: {type(exc).__name__}: {exc}"
        log.exception(report["error"])
        return report

    antbb_static = backup / "antbb" / "web" / "static"
    yellow_static = Path(os.environ.get("YELLOW_QUEEN_ROOT", "/home/lordix/yellow-queen")) / "yellow_queen" / "web" / "static"
    serve_static = _dual_static(antbb_static, yellow_static)

    # Remove any prior /static Mount so dual static wins.
    app.router.routes[:] = [
        r
        for r in app.router.routes
        if not (isinstance(r, Mount) and getattr(r, "path", None) == "/static")
    ]

    @app.get("/static/{full_path:path}", include_in_schema=False)
    async def merged_static(full_path: str):
        return await serve_static(full_path)

    report["added"].append("/static (dual antbb+yellow)")

    def _methods(route) -> frozenset:
        return frozenset(getattr(route, "methods", None) or {"GET"})

    # Pfad -> bereits gemountete Methoden. Gleicher Pfad mit DISJUNKTEN Methoden
    # (z.B. GET + POST /api/wlan/floorplan) darf nicht verworfen werden.
    existing: dict[str, frozenset] = {}
    for r in app.router.routes:
        p = getattr(r, "path", None)
        if p:
            existing[p] = existing.get(p, frozenset()) | _methods(r)
    for route in list(colony.router.routes):
        if isinstance(route, Mount):
            report["skipped"].append(f"mount:{getattr(route, 'path', '?')}")
            continue
        path = getattr(route, "path", None)
        if not path or path in SKIP_EXACT:
            report["skipped"].append(path or "?")
            continue
        if path not in YELLOW_COLONY_ALLOW and any(
            path == p or path.startswith(p.rstrip("/") + "/") or path.startswith(p)
            for p in SKIP_PREFIXES
        ):
            report["skipped"].append(path)
            continue
        methods = _methods(route)
        if path in existing and (existing[path] & methods):
            report["skipped"].append(f"{path} (exists)")
            continue
        app.router.routes.insert(0, route)
        existing[path] = existing.get(path, frozenset()) | methods
        report["added"].append(path)

    # /red is the classic Rote Königin (antbb.web.app.index). The colony
    # app's "/" is the All-and-One landing, so wrapping that endpoint made
    # GET /red serve the hub (and Next.js <Link> then prefetched /red.txt).
    # Older trees that still serve the queen at "/" are the fallback.
    red_endpoint = None
    index_endpoint = None
    for route in colony.router.routes:
        path = getattr(route, "path", None)
        if path == "/red" and hasattr(route, "endpoint"):
            red_endpoint = route.endpoint
        elif path == "/" and hasattr(route, "endpoint"):
            index_endpoint = route.endpoint
    queen_endpoint = red_endpoint or index_endpoint

    # Ensure chrome FileResponses / prior /red /blue do not shadow colony.
    app.router.routes[:] = [
        r for r in app.router.routes
        if getattr(r, "path", None) not in {"/red", "/blue"}
    ]
    # Re-add colony /blue and /red (prefer the real /red route).
    for want in ("/blue", "/red"):
        for route in list(colony.router.routes):
            if getattr(route, "path", None) == want:
                app.router.routes.insert(0, route)
                break

    if any(getattr(r, "path", None) == "/red" for r in app.router.routes):
        report["added"].append("/red -> colony /red (classic queen)")
        report["red"] = "/red"
    elif queen_endpoint is not None:
        @app.get("/red", response_class=HTMLResponse, include_in_schema=False)
        def red_colony(request: Request):
            return queen_endpoint(request)

        report["added"].append("/red -> colony queen endpoint (same-origin)")
        report["red"] = "/red"
    else:
        @app.get("/red", include_in_schema=False)
        def red_fallback():
            return RedirectResponse("/", status_code=302)

        report["red"] = "/red (fallback redirect)"

    if any(getattr(r, "path", None) == "/blue" for r in app.router.routes):
        report["blue"] = "/blue"
    else:
        report["blue"] = None
        report["error"] = (report.get("error") or "") + " /blue missing after mount"

    # Convenience: classic alias
    @app.get("/classic", include_in_schema=False)
    def classic_alias():
        return RedirectResponse("/red", status_code=302)

    report["added"].append("/classic -> /red")

    # insert(0) while iterating colony routes reverses their relative order, so
    # /api/brain/{target_id} would otherwise sit ahead of literal /nodes and
    # /logs and 422 them (FastAPI matches in list order). Same fix as
    # antbb.web.app._reorder_brain_routes.
    routes = app.router.routes
    for r in list(routes):
        if getattr(r, "path", None) == "/api/brain/{target_id}":
            routes.remove(r)
            routes.append(r)

    report["ok"] = True
    log.info("colony mount ok added=%s", len(report["added"]))
    return report
