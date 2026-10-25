"""Mount Yellow Queen RE (~/yellow-queen) into All-and-One on :1001."""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from starlette.routing import Mount

log = logging.getLogger("allone.yellow")

YQ_ROOT = Path(os.environ.get("YELLOW_QUEEN_ROOT", os.environ.get("YQ_HOME", "/home/lordix/yellow-queen")))
TOOLS_ENV = Path(os.environ.get("YELLOW_TOOLS_ENV", "/home/lordix/yellow-tools/env.sh"))

SKIP_EXACT = {
    "/",
    "/api/health",
    "/api/brain",
    "/yellow/brain",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
    "/red",
    "/blue",
    "/brain",
}


def _load_tools_env() -> None:
    if not TOOLS_ENV.is_file():
        return
    home = os.environ.get("HOME", "/home/lordix")
    for line in TOOLS_ENV.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip("'").strip('"')
        val = val.replace("$HOME", home).replace("${HOME}", home)
        if "YELLOW_TOOLS" in os.environ:
            val = val.replace("$YELLOW_TOOLS", os.environ["YELLOW_TOOLS"]).replace(
                "${YELLOW_TOOLS}", os.environ["YELLOW_TOOLS"]
            )
        if key == "PATH":
            os.environ["PATH"] = val.replace("$PATH", os.environ.get("PATH", ""))
        else:
            os.environ.setdefault(key, val)
    os.environ.setdefault("YQ_TOOLS_PATH", str(Path(home) / "yellow-tools" / "bin"))
    bindir = os.environ.get("YQ_TOOLS_PATH", "")
    if bindir and bindir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = bindir + os.pathsep + os.environ.get("PATH", "")


def attach_yellow(app: FastAPI) -> dict:
    """Register Yellow pages + upload APIs. /yellow/brain -> shared /brain."""
    _load_tools_env()
    root = str(YQ_ROOT.resolve())
    if root not in sys.path:
        sys.path.insert(0, root)
    os.environ.setdefault("YQ_HOME", root)

    try:
        from yellow_queen.web.app import app as yellow_app  # noqa: WPS433
    except Exception as exc:  # noqa: BLE001
        log.exception("yellow import failed: %s", exc)
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "attached": []}

    attached = []
    existing = {getattr(r, "path", None) for r in app.router.routes}

    for route in list(yellow_app.routes):
        if isinstance(route, Mount):
            continue
        path = getattr(route, "path", None)
        if not path or path in SKIP_EXACT:
            continue
        keep = (
            path == "/yellow"
            or path.startswith("/yellow/")
            or path in {
                "/api/cases",
                "/api/classify",
                "/api/doctor",
                "/api/demo/elf",
                "/faelle",
                "/gates",
                "/playbooks",
            }
            or path.startswith("/api/cases/")
            or path.startswith("/yellow/case/")
            or path.startswith("/faelle/")
            or path.startswith("/playbooks/")
            or path.startswith("/api/brain/snapshot")
            or (path.startswith("/api/brain/") and path != "/api/brain")
        )
        if not keep:
            continue
        app.router.routes.insert(0, route)
        existing.add(path)
        attached.append(path)

    
    # GET /yellow/upload → echtes same-origin Formular, kein Seitenumweg.
    yellow_index = next(
        route.endpoint for route in yellow_app.routes if getattr(route, "path", None) == "/yellow"
    )

    @app.get("/yellow/upload", include_in_schema=False)
    def yellow_upload_get(request: Request):
        return yellow_index(request)

    @app.get("/yellow/brain", include_in_schema=False)
    def yellow_brain_redirect(case: str | None = None):
        q = "/brain?queen=yellow"
        if case:
            q += f"&case={case}"
        return RedirectResponse(q, status_code=302)

    @app.get("/api/yellow/health", include_in_schema=False)
    def api_yellow_health():
        try:
            from yellow_queen import QUEEN_ID, __version__  # noqa: WPS433
            return {
                "ok": True,
                "queen_id": QUEEN_ID,
                "version": __version__,
                "service": "yellow-queen-re",
            }
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    attached.append("/yellow/brain->/brain")
    attached.append("/api/yellow/health")
    log.info("yellow mount attached=%s", attached)
    return {"ok": True, "attached": attached, "yq_root": root}
