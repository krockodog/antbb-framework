"""All and One — Erweiterungen am selben FastAPI-Prozess.

Haengt zusaetzliche, same-origin API-Routen an den EINEN Prozess (Port 1001):
  * /api/queens/{queen}/skills       — CRUD der Skills pro Koenigin
  * /api/queens/{queen}/custom-playbooks — CRUD der Nutzer-Playbooks pro Koenigin
  * /api/catalog                     — Skills/Playbooks-Bilanz je Koenigin
  * /api/ai, /api/ai/{queen}         — Provider-Katalog + Zuweisung (optional)

Die Skill-Dateien liegen unter data/skills/<queen>/*.md (Frontmatter +
Markdown-Body, siehe allone_skills). Alles optional und defensiv: faellt ein
Teil aus, bleibt die Kern-UI online.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


class ProviderBody(BaseModel):
    provider: str = Field(min_length=1, max_length=40)


class SkillBody(BaseModel):
    title: str = Field(min_length=1, max_length=180)
    body: str = Field(default="", max_length=200000)
    id: str | None = Field(default=None, max_length=80)


class SkillPatch(BaseModel):
    title: str | None = Field(default=None, max_length=180)
    body: str | None = Field(default=None, max_length=200000)


class PlaybookBody(BaseModel):
    title: str = Field(min_length=1, max_length=180)
    summary: str = Field(default="", max_length=400)
    kind: str = Field(default="custom", max_length=40)
    id: str | None = Field(default=None, max_length=80)


class PlaybookPatch(BaseModel):
    title: str | None = None
    summary: str | None = None
    kind: str | None = None
    needs_probe: bool | None = None


def attach_extensions(app: FastAPI) -> dict:
    import allone_skills as sk

    mounted: dict[str, bool] = {"skills": True, "custom_playbooks": True,
                                "ai": False, "catalog": True}

    @app.exception_handler(sk.SkillError)
    async def _skill_err(_r: Request, exc: sk.SkillError) -> JSONResponse:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status)

    # ---- AI (optional: nur wenn der gebrandete Router importierbar ist) ----
    try:
        import allone_ai as ai

        @app.get("/api/ai")
        def ai_status() -> dict:
            return ai.status()

        @app.put("/api/ai/{queen}")
        def ai_assign(queen: str, body: ProviderBody) -> dict:
            try:
                return ai.set_assignment(queen, body.provider)
            except ValueError as exc:
                return JSONResponse({"detail": str(exc)}, status_code=400)

        mounted["ai"] = True
    except Exception:  # noqa: BLE001
        ai = None  # Router nicht verfuegbar — AI-Routen einfach weglassen.

    # ---- Skills CRUD ----
    @app.get("/api/queens/{queen}/skills")
    def skills_list(queen: str) -> dict:
        return {"queen": queen, "skills": sk.list_skills(queen)}

    @app.post("/api/queens/{queen}/skills")
    def skills_create(queen: str, body: SkillBody) -> dict:
        return sk.create_skill(queen, body.title, body.body, body.id)

    @app.get("/api/queens/{queen}/skills/{sid}")
    def skills_get(queen: str, sid: str) -> dict:
        return sk.get_skill(queen, sid)

    @app.put("/api/queens/{queen}/skills/{sid}")
    def skills_update(queen: str, sid: str, body: SkillPatch) -> dict:
        return sk.update_skill(queen, sid, body.title, body.body)

    @app.delete("/api/queens/{queen}/skills/{sid}")
    def skills_delete(queen: str, sid: str) -> dict:
        return sk.delete_skill(queen, sid)

    # ---- Custom Playbooks CRUD ----
    @app.get("/api/queens/{queen}/custom-playbooks")
    def pb_list(queen: str) -> dict:
        return {"queen": queen, "playbooks": sk.list_playbooks(queen)}

    @app.post("/api/queens/{queen}/custom-playbooks")
    def pb_create(queen: str, body: PlaybookBody) -> dict:
        return sk.create_playbook(queen, body.title, body.summary, body.kind, body.id)

    @app.get("/api/queens/{queen}/custom-playbooks/{pid}")
    def pb_get(queen: str, pid: str) -> dict:
        return sk.get_playbook(queen, pid)

    @app.put("/api/queens/{queen}/custom-playbooks/{pid}")
    def pb_update(queen: str, pid: str, body: PlaybookPatch) -> dict:
        return sk.update_playbook(queen, pid, body.model_dump(exclude_none=True))

    @app.delete("/api/queens/{queen}/custom-playbooks/{pid}")
    def pb_delete(queen: str, pid: str) -> dict:
        return sk.delete_playbook(queen, pid)

    # ---- Catalog overview ----
    @app.get("/api/catalog")
    def catalog() -> dict:
        return {"skills_playbooks": sk.summary(),
                "ai": ai.load_assignments() if ai else None}

    # Reihenfolge: unsere /api-Routen MUESSEN vor der UI-Catch-all-Route
    # ("/{full_path:path}") stehen, die beim create_app() zuerst registriert
    # wurde. Sonst verschluckt die UI die neuen GET-Endpunkte. Wir schieben die
    # Catch-all-Routen deshalb ans Ende der Routen-Liste.
    routes = app.router.routes
    catch = [r for r in routes if "{full_path" in getattr(r, "path", "")]
    for r in catch:
        routes.remove(r)
        routes.append(r)
    return {"ok": True, **mounted}
