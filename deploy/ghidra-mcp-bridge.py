#!/usr/bin/env python3
"""Loopback HTTP bridge so Yellow's ghidra-mcp client can use official analyzeHeadless.

Binds 127.0.0.1:8089 only. Endpoints used by yellow-queen/orchestrator.py:
  GET  /check_connection
  POST /import_file   {file_path, project_path, project_name}
  GET  /find_functions?limit=&offset=
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HOST = os.environ.get("GHIDRA_MCP_BIND", "127.0.0.1")
PORT = int(os.environ.get("GHIDRA_MCP_PORT", "8089"))
GHIDRA = os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra")
HEADLESS = os.environ.get(
    "GHIDRA_HEADLESS",
    str(Path(GHIDRA) / "support" / "analyzeHeadless"),
)
SCRIPT = os.environ.get(
    "GHIDRA_EXPORT_SCRIPT",
    "/opt/antbb-tools/ghidra-scripts/ExportFunctions.py",
)
JAVA_HOME = os.environ.get("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-arm64")

_STATE = {"last": None}


def _json(handler: BaseHTTPRequestHandler, code: int, body: dict) -> None:
    raw = json.dumps(body).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(raw)


def _import_file(payload: dict) -> dict:
    sample = Path(payload.get("file_path") or "")
    if not sample.is_file():
        return {"success": False, "error": "file_path missing or not a file"}
    proj = Path(payload.get("project_path") or tempfile.mkdtemp(prefix="ghidra-proj-"))
    proj.mkdir(parents=True, exist_ok=True)
    name = payload.get("project_name") or "case"
    out_json = proj / "ghidra-functions.json"
    env = os.environ.copy()
    env["JAVA_HOME"] = JAVA_HOME
    env["PATH"] = f"{JAVA_HOME}/bin:" + env.get("PATH", "")
    script_dir = str(Path(SCRIPT).parent)
    cmd = [
        HEADLESS, str(proj), name,
        "-import", str(sample),
        "-scriptPath", script_dir,
        "-postScript", Path(SCRIPT).name, str(out_json),
        "-deleteProject",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
    log = (proc.stdout or "")[-4000:] + (proc.stderr or "")[-2000:]
    (proj / "analyzeHeadless.log").write_text(log, encoding="utf-8", errors="replace")
    if out_json.is_file():
        data = json.loads(out_json.read_text(encoding="utf-8"))
        data["success"] = True
        _STATE["last"] = data
        return data
    return {
        "success": False,
        "error": f"analyzeHeadless rc={proc.returncode}",
        "log_excerpt": log[-800:],
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # quieter
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/check_connection":
            version = "unknown"
            try:
                r = subprocess.run([HEADLESS, "-help"], capture_output=True, text=True, timeout=15)
                version = (r.stdout or r.stderr or "").splitlines()[0][:120] or "analyzeHeadless"
            except Exception:
                version = "analyzeHeadless"
            _json(self, 200, {"status": "ok", "server_kind": "headless",
                              "version": version, "adapter": "official-analyzeHeadless"})
            return
        if parsed.path == "/find_functions":
            qs = parse_qs(parsed.query)
            limit = int((qs.get("limit") or ["500"])[0] or 500)
            offset = int((qs.get("offset") or ["0"])[0] or 0)
            last = _STATE.get("last") or {}
            funcs = list(last.get("functions") or [])
            batch = funcs[offset:offset + limit]
            _json(self, 200, {"functions": batch, "total": len(funcs),
                              "offset": offset, "limit": limit})
            return
        _json(self, 404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            _json(self, 400, {"success": False, "error": "invalid json"})
            return
        if parsed.path == "/import_file":
            _json(self, 200, _import_file(payload if isinstance(payload, dict) else {}))
            return
        _json(self, 404, {"error": "not found"})


def main() -> None:
    if HOST not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit(f"Refusing to bind non-loopback address {HOST}")
    if not Path(HEADLESS).is_file():
        raise SystemExit(f"analyzeHeadless not found at {HEADLESS}")
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"ghidra-mcp-bridge listening on http://{HOST}:{PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
