"""HTTP-Fläche für All and One - RED-BLUE-Yellow-Ant-Team."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from api.catalog import (
    ANTBB_UNIT,
    ANTBB_WORKDIR,
    DESCRIPTION,
    FOOTER,
    LEGAL_NOTICE,
    NOUNS,
    PRODUCT,
    QUEEN_IDS,
    SURFACE_HOST,
    SURFACE_ORIGIN,
    SURFACE_PORT,
)
from api.store import ColonyError, Settings, Store
from api.ui import attach_ui


class QueenId(str, Enum):
    red = "red"
    blue = "blue"
    yellow = "yellow"


class ScopeBody(BaseModel):
    allow: list[str] = Field(default_factory=list)


class OversightBody(BaseModel):
    armed: bool


class RunBody(BaseModel):
    soldier_id: str = Field(min_length=1, max_length=64)
    playbook_id: str = Field(min_length=1, max_length=80)
    oversight: bool
    targets: list[str] = Field(default_factory=list)
    probe_name: str | None = None


class ClassifyBody(BaseModel):
    name: str = Field(min_length=1, max_length=180)
    declared_kind: Literal["pe", "dotnet", "apk", "elf", "hex", "dos"] | None = None
    oversight: bool = False


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    store = Store(settings)
    app = FastAPI(title=PRODUCT, version="1.0.0")
    app.state.store = store
    app.state.settings = settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(ColonyError)
    async def colony_error(_request: Request, exc: ColonyError) -> JSONResponse:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status)

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "service": "all-and-one", "queen_ids": list(QUEEN_IDS)}

    @app.get("/api/health/{queen_id}")
    def health_queen(queen_id: QueenId) -> dict:
        return {"ok": True, "queen_id": queen_id.value, "service": "all-and-one"}

    @app.get("/api/legal")
    def legal() -> dict:
        return {
            "product": PRODUCT,
            "notice": LEGAL_NOTICE,
            "replaces_oversight": False,
        }

    @app.get("/red.txt", include_in_schema=False)
    def red_txt() -> PlainTextResponse:
        detail = store.queen_detail("red")
        runs = detail.get("runs", [])
        lines = [
            "All and One · Red Queen",
            f"Scope: {', '.join(detail.get('scope') or ['(leer)'])}",
            f"Oversight: {'armed' if detail.get('oversight') else 'disarmed'}",
            f"Soldaten: {len(detail.get('soldier_ids') or [])}",
            f"Playbooks: {len(detail.get('playbook_ids') or [])}",
            f"Laeufe: {len(runs)}",
        ]
        return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; charset=utf-8")

    @app.get("/api/meta")
    def meta() -> dict:
        return {
            "product": PRODUCT,
            "description": DESCRIPTION,
            "footer": FOOTER,
            "queen_ids": list(QUEEN_IDS),
            "nouns": list(NOUNS),
            "surface": {
                "host": SURFACE_HOST,
                "port": SURFACE_PORT,
                "process": "one",
                "origin": SURFACE_ORIGIN,
            },
            "service": {"unit": ANTBB_UNIT, "working_directory": ANTBB_WORKDIR},
            "roles": {
                "red": "Red-Teaming",
                "blue": "Blue Safety-Teaming",
                "yellow": "Yellow Reverse-Teaming",
            },
            "ports_documented": {"surface": SURFACE_PORT},
        }

    @app.get("/api/queens")
    def queens() -> list[dict]:
        return [store.queen_summary(queen) for queen in QUEEN_IDS]

    @app.get("/api/queens/{queen_id}")
    def queen_detail(queen_id: QueenId) -> dict:
        return store.queen_detail(queen_id.value)

    @app.get("/api/queens/{queen_id}/soldiers")
    def soldiers(queen_id: QueenId) -> dict:
        detail = store.queen_detail(queen_id.value)
        return {"queen_id": queen_id.value, "soldiers": detail["soldiers"]}

    @app.get("/api/queens/{queen_id}/soldiers/{soldier_id}")
    def soldier(queen_id: QueenId, soldier_id: str) -> dict:
        detail = store.queen_detail(queen_id.value)
        for item in detail["soldiers"]:
            if item["soldier_id"] == soldier_id:
                return item
        raise ColonyError(404, "Diese Soldatin gehört nicht zu dieser Königin.")

    @app.get("/api/queens/{queen_id}/playbooks")
    def playbooks(queen_id: QueenId) -> dict:
        detail = store.queen_detail(queen_id.value)
        return {"queen_id": queen_id.value, "playbooks": detail["playbooks"]}

    @app.get("/api/queens/{queen_id}/playbooks/{playbook_id}")
    def playbook(queen_id: QueenId, playbook_id: str) -> dict:
        detail = store.queen_detail(queen_id.value)
        for item in detail["playbooks"]:
            if item["playbook_id"] == playbook_id:
                return item
        raise ColonyError(404, "Dieses Playbook gehört nicht zu dieser Königin.")

    @app.get("/api/queens/{queen_id}/scope")
    def scope(queen_id: QueenId) -> dict:
        summary = store.queen_summary(queen_id.value)
        return {
            "queen_id": queen_id.value,
            "mode": "default-deny",
            "allow": summary["scope"],
        }

    @app.put("/api/queens/{queen_id}/scope")
    def put_scope(queen_id: QueenId, body: ScopeBody) -> dict:
        return store.set_scope(queen_id.value, body.allow)

    @app.post("/api/queens/{queen_id}/oversight")
    def post_oversight(queen_id: QueenId, body: OversightBody) -> dict:
        return store.set_oversight(queen_id.value, body.armed)

    @app.get("/api/queens/{queen_id}/runs")
    def runs(queen_id: QueenId) -> dict:
        return {"queen_id": queen_id.value, "runs": store.list_runs(queen_id.value)}

    @app.get("/api/queens/{queen_id}/runs/{run_id}")
    def run_detail(queen_id: QueenId, run_id: str) -> dict:
        return store.get_run(queen_id.value, run_id)

    @app.post("/api/queens/{queen_id}/runs")
    def start_run(queen_id: QueenId, body: RunBody) -> dict:
        return store.start_run(
            queen_id.value,
            body.soldier_id,
            body.playbook_id,
            body.oversight,
            body.targets,
            body.probe_name,
        )

    @app.get("/api/queens/{queen_id}/ledger")
    def ledger(queen_id: QueenId) -> dict:
        return {"queen_id": queen_id.value, "ledger": store.ledger(queen_id.value)}

    @app.post("/api/queens/yellow/classify")
    def classify_probe(body: ClassifyBody) -> dict:
        return store.classify_probe(body.name, body.declared_kind, body.oversight)

    @app.get("/api/brain")
    def brain(queen: QueenId | None = None) -> dict:
        payload = store.brain()
        payload["focus"] = queen.value if queen else None
        return payload

    @app.get("/truppen", include_in_schema=False)
    def truppen() -> HTMLResponse:
        from api.truppen import render_truppen

        return HTMLResponse(render_truppen(store))

    # REAL antbb colony (backup) — Red/Blue scope + scans, dual /static
    try:
        from api.colony_mount import attach_colony

        app.state.colony_mount = attach_colony(app)
    except Exception as exc:  # noqa: BLE001
        import logging

        logging.getLogger("allone").exception("Colony-Mount fehlgeschlagen: %s", exc)
        app.state.colony_mount = {"ok": False, "error": str(exc)}

    # Yellow Queen RE — real EXE/PE upload + cases
    try:
        from api.yellow_mount import attach_yellow

        app.state.yellow_mount = attach_yellow(app)
    except Exception as exc:  # noqa: BLE001
        import logging

        logging.getLogger("allone").exception("Yellow-Mount fehlgeschlagen: %s", exc)
        app.state.yellow_mount = {"ok": False, "error": str(exc)}

    # All and One — Skills/Custom-Playbooks-CRUD + Katalog-Bilanz je Koenigin
    # (Dateisystem unter data/skills + data/custom-playbooks; siehe allone_skills).
    try:
        from api.extensions import attach_extensions

        app.state.extensions_mount = attach_extensions(app)
    except Exception as exc:  # noqa: BLE001
        import logging

        logging.getLogger("allone").exception("Extensions-Mount fehlgeschlagen: %s", exc)
        app.state.extensions_mount = {"ok": False, "error": str(exc)}

    @app.get("/api/mounts")
    def mounts() -> dict:
        return {
            "colony": getattr(app.state, "colony_mount", None),
            "yellow": getattr(app.state, "yellow_mount", None),
            "extensions": getattr(app.state, "extensions_mount", None),
        }

    web_root = Path(os.environ.get("ALLONE_WEB_ROOT", Path(__file__).resolve().parents[1] / "all-and-one" / "out"))
    attach_ui(app, web_root)
    return app


app = create_app()
