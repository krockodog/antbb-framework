"""Eine Oberflaeche, vom selben Prozess ausgeliefert wie die API."""

from __future__ import annotations

import mimetypes
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse

mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("font/woff2", ".woff2")

MISSING = {
    "detail": "Die Oberflaeche ist noch nicht gebaut. Im Archiv liegt all-and-one/out, sonst npm --prefix all-and-one run build.",
}

RESERVED_PREFIXES = (
    "api/",
    "target/",
    "yellow",
    "yellow/",
    "yellow/upload",
    "yellow/case/",
    "red",
    "blue",
    "classic",
    "faelle",
    "gates",
    "playbooks",
    "providers",
    "auth/",
    "wlan",
    "trash",
    "report/",
    "remote/",
    "static/",
)


def _safe(root: Path, full_path: str) -> Path | None:
    root = root.resolve()
    relative = full_path.strip("/")
    if relative == "api" or relative.startswith("api/") or chr(92) in relative:
        return None
    parts = Path(relative).parts if relative else ()
    if ".." in parts:
        return None
    bases = [root / "index.html"] if not relative else [root / relative]
    if relative:
        base = root / relative
        bases.extend((Path(str(base) + ".html"), base / "index.html"))
    for candidate in bases:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved != root and root not in resolved.parents:
            continue
        if resolved.is_file():
            return resolved
    return None


def attach_ui(app: FastAPI, root: Path) -> None:
    @app.get("/", include_in_schema=False, response_model=None)
    def home() -> FileResponse | JSONResponse:
        page = _safe(root, "")
        if page is None:
            return JSONResponse(MISSING, status_code=503)
        return FileResponse(page)

    @app.get("/yellow/laeufe", include_in_schema=False, response_model=None)
    def yellow_laeufe() -> FileResponse | JSONResponse:
        page = _safe(root, "yellow/laeufe")
        if page is None:
            return JSONResponse({"detail": "yellow/laeufe ist nicht gebaut."}, status_code=404)
        return FileResponse(page)

    def _colony_brain() -> FileResponse | JSONResponse:
        # Kolonie-spezifische Brain-Aliasse zeigen auf das geteilte neuronale Gehirn.
        page = _safe(root, "brain")
        if page is None:
            return JSONResponse(MISSING, status_code=503)
        return FileResponse(page)

    app.add_api_route("/red/brain", _colony_brain, methods=["GET"], include_in_schema=False, response_model=None)
    app.add_api_route("/blue/brain", _colony_brain, methods=["GET"], include_in_schema=False, response_model=None)

    @app.get("/{full_path:path}", include_in_schema=False, response_model=None)
    def asset(full_path: str) -> FileResponse | JSONResponse:
        lowered = full_path.strip("/")
        if any(lowered == p.rstrip("/") or lowered.startswith(p) for p in RESERVED_PREFIXES):
            return JSONResponse({"detail": "Diesen Pfad kenne ich nicht."}, status_code=404)
        page = _safe(root, full_path)
        if page is None:
            missing = _safe(root, "404.html")
            if missing is not None:
                return FileResponse(missing, status_code=404)
            return JSONResponse({"detail": "Diese Route kenne ich nicht."}, status_code=404)
        return FileResponse(page)
