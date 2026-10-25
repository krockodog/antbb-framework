"""Yellow Queen Web: /, /yellow, /yellow/brain, /api/*  (FastAPI)."""
from __future__ import annotations

import re
import tempfile
import threading
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import QUEEN_ID, __version__, config, db
from ..doctor import run_doctor
from ..gates import GATE_TEXT_DE, GateError, check
from ..queen import neural_brain, orchestrator

HERE = Path(__file__).resolve().parent
app = FastAPI(title="Yellow Queen RE", version=__version__)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
templates = Jinja2Templates(directory=str(HERE / "templates"))
CASE_RX = re.compile(r"^yq-[0-9A-Za-z-]{6,64}$")
DOC_FILES = {"ledger.md", "dossier.md"}


config.ensure_dirs()
with db.conn():  # Schema anlegen (data/yellow.db)
    pass


@app.middleware("http")
async def headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Security-Policy"] = "frame-ancestors http://192.168.2.7:1001 http://127.0.0.1:1001 'self'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def _ctx(request: Request, **kw):
    return {"request": request, "queen_id": QUEEN_ID, "version": __version__, "gate_text": GATE_TEXT_DE, **kw}


# ---------- Seiten ----------
@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(request, "home.html", _ctx(request, error=None, max_mb=config.MAX_UPLOAD_BYTES // (1024 * 1024)))


@app.get("/yellow")
def yellow(request: Request, error: Optional[str] = None):
    return templates.TemplateResponse(request, "yellow.html", _ctx(
        request, cases=db.list_cases(50), doctor=run_doctor(False), host=config.HOST, port=config.PORT,
        error=error, max_mb=config.MAX_UPLOAD_BYTES // (1024 * 1024)))


@app.get("/yellow/brain")
def brain(request: Request, case: Optional[str] = None):
    if case and not CASE_RX.match(case):
        raise HTTPException(400, "Ungültige Fall-ID")
    return templates.TemplateResponse(request, "brain.html", _ctx(request, case=case, snapshot=neural_brain.read_snapshot(case)))


@app.get("/yellow/case/{case_id}")
def case_page(request: Request, case_id: str):
    case = _case_or_404(case_id)
    cdir = Path(case["case_path"])
    ev = sorted(p.name for p in (cdir / "evidence").glob("*") if p.is_file() and p.name != "sample.bin")
    dossier = (cdir / "dossier.md")
    snap = neural_brain.read_snapshot(case_id)
    # Defaults, falls alter Snapshot noch keine UI-Felder hat
    snap.setdefault("next3_steps", [])
    snap.setdefault("findings", [])
    snap.setdefault("bypass", {"id": "bypass", "label": "Bypass", "status": "pending", "playbook": "–",
                               "requires_oversight": False, "warum": "", "fund": "", "next": []})
    snap.setdefault("dynamic_step", {"id": "dynamic", "label": "Dynamic-Lab", "status": "pending",
                                    "playbook": "dynamic-lab", "requires_oversight": True,
                                    "warum": "", "fund": "", "next": [], "tools_used": []})
    snap.setdefault("last_ran_at", case.get("updated_at"))
    return templates.TemplateResponse(request, "case.html", _ctx(
        request, case=case, evidence=ev, snap=snap,
        dossier=dossier.read_text("utf-8") if dossier.exists() else "(Dossier folgt nach dem Merge)"))


@app.get("/yellow/case/{case_id}/{doc}")
def case_doc(case_id: str, doc: str):
    case = _case_or_404(case_id)
    if doc not in DOC_FILES:
        raise HTTPException(404)
    p = Path(case["case_path"]) / doc
    if not p.exists():
        raise HTTPException(404, "Noch nicht erzeugt")
    return PlainTextResponse(p.read_text("utf-8"), media_type="text/markdown; charset=utf-8")


@app.get("/yellow/case/{case_id}/evidence/{name}")
def case_evidence(case_id: str, name: str):
    case = _case_or_404(case_id)
    if "/" in name or "\\" in name or name in {"sample.bin", ".", ".."}:
        raise HTTPException(404)
    p = Path(case["case_path"]) / "evidence" / name
    if not p.is_file():
        raise HTTPException(404)
    return FileResponse(p, media_type="text/plain; charset=utf-8")  # nie als HTML/ausführbar ausliefern


def _case_or_404(case_id: str) -> dict:
    if not CASE_RX.match(case_id):
        raise HTTPException(400, "Ungültige Fall-ID")
    c = db.get_case(case_id)
    if not c:
        raise HTTPException(404, "Fall nicht gefunden")
    return c


# ---------- Upload ----------
def _receive(file: UploadFile) -> Path:
    tmp_dir = config.DATA_DIR / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd = tempfile.NamedTemporaryFile(dir=tmp_dir, delete=False, suffix=".upload")
    size = 0
    try:
        with fd:
            while chunk := file.file.read(1 << 20):
                size += len(chunk)
                if size > config.MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"Datei zu groß (max. {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB, YQ_MAX_UPLOAD_MB)")
                fd.write(chunk)
        if size == 0:
            raise HTTPException(400, "Leere Datei")
    except BaseException:
        Path(fd.name).unlink(missing_ok=True)
        raise
    return Path(fd.name)


@app.post("/api/classify")
def api_classify(file: UploadFile = File(...), authorized: str = Form(""), dynamic: str = Form(""), oversight: str = Form("")):
    try:
        gate = check(authorized, dynamic, oversight)  # Gate VOR jedem Speichern
    except GateError as e:
        return JSONResponse({"queen_id": QUEEN_ID, "ok": False, "gate": "autorisierung", "detail": str(e)}, status_code=403)
    tmp = _receive(file)
    case = orchestrator.create_case(tmp, file.filename, gate)
    result = orchestrator.run_case(case["id"], gate)
    return _public_case(result)


@app.post("/yellow/upload")
def upload_form(request: Request, file: UploadFile = File(...), authorized: str = Form(""), dynamic: str = Form(""), oversight: str = Form("")):
    try:
        gate = check(authorized, dynamic, oversight)
    except GateError as e:
        return templates.TemplateResponse(
            request, "yellow.html",
            _ctx(request, error=str(e), max_mb=config.MAX_UPLOAD_BYTES // (1024 * 1024),
                 cases=db.list_cases(50), doctor=run_doctor(False), host=config.HOST, port=config.PORT),
            status_code=403)
    tmp = _receive(file)
    case = orchestrator.create_case(tmp, file.filename, gate)
    threading.Thread(target=orchestrator.run_case, args=(case["id"], gate), daemon=True, name=f"yq-{case['id']}").start()
    # Fall-Seite: Next-3, Ergebnisse, Bypass — nicht das zweite Brain
    return RedirectResponse(f"/yellow/case/{case['id']}", status_code=303)


def _public_case(c: dict) -> dict:
    cid = c.get("id")
    return {
        "queen_id": QUEEN_ID, "ok": c.get("status") == "done", "case_id": cid, "status": c.get("status"), "filename": c.get("filename"),
        "sha256": c.get("sha256"), "size": c.get("size"), "kind": c.get("kind"), "route": c.get("route"), "packed": bool(c.get("packed")),
        "dynamic": c.get("dynamic"), "created_at": c.get("created_at"),
        "hops": [{k: h[k] for k in ("idx", "op", "skill", "status", "summary_de", "warum", "fund", "next")} for h in c.get("hops", [])],
        "links": {"case": f"/yellow/case/{cid}", "brain": f"/yellow/brain?case={cid}", "dossier": f"/yellow/case/{cid}/dossier.md",
                  "ledger": f"/yellow/case/{cid}/ledger.md"},
    }


# ---------- API ----------
@app.get("/api/health")
def health():
    return {"ok": True, "queen_id": QUEEN_ID, "service": "yellow-queen-re", "version": __version__, "time": config.now_iso(),
            "port": config.PORT, "db": str(config.DB_PATH.name)}


@app.get("/api/brain/snapshot")
def api_snapshot(case: Optional[str] = None):
    if case and not CASE_RX.match(case):
        raise HTTPException(400, "Ungültige Fall-ID")
    return neural_brain.read_snapshot(case)


@app.get("/api/doctor")
def api_doctor(versions: bool = True):
    return run_doctor(versions)


@app.get("/api/cases")
def api_cases():
    return {"queen_id": QUEEN_ID, "cases": db.list_cases(200)}


@app.get("/api/cases/{case_id}")
def api_case(case_id: str):
    return _public_case(_case_or_404(case_id))


# ---------------- RE-Orchestrator: echte Schritte + Next-Steps ----------------
from .. import orchestrator as _orch


def _orch_dir(case_id: str) -> Path:
    if not CASE_RX.match(case_id):
        raise HTTPException(400, "case_id ungültig")
    return _orch.case_dir(Path(config.DATA_DIR), case_id)


@app.get("/yellow/case/{case_id}/orchestrate/state")
def orch_state(case_id: str):
    d = _orch_dir(case_id)
    state = _orch.load_state(d)
    state["next_steps"] = [s for s in _orch.next_steps(state) if s["action"] != "none"]
    return JSONResponse({"ok": True, "case_id": case_id, "state": state})


@app.post("/yellow/case/{case_id}/orchestrate/step")
def orch_step(case_id: str, payload: dict):
    d = _orch_dir(case_id)
    result = _orch.run_step(
        Path(config.DATA_DIR), case_id,
        str(payload.get("action") or ""),
        bool(payload.get("oversight_ok")),
    )
    return JSONResponse(result)
