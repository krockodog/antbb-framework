"""Konfiguration über Umgebungsvariablen. Keine Secrets – nichts davon wird gespeichert."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("YQ_HOME") or Path(__file__).resolve().parent.parent).resolve()
DATA_DIR = Path(os.environ.get("YQ_DATA_DIR") or ROOT / "data").resolve()
CASES_DIR = Path(os.environ.get("YQ_CASES_DIR") or ROOT / "cases").resolve()
NOTES_DIR = Path(os.environ.get("YQ_NOTES_DIR") or ROOT / "notes").resolve()
SCHEMAS_DIR = ROOT / "schemas"
DB_PATH = DATA_DIR / "yellow.db"
HOST = os.environ.get("YQ_HOST", "0.0.0.0")
PORT = int(os.environ.get("YQ_PORT", "1016"))
MAX_UPLOAD_BYTES = int(float(os.environ.get("YQ_MAX_UPLOAD_MB", "150")) * 1024 * 1024)
TOOL_TIMEOUT = int(os.environ.get("YQ_TOOL_TIMEOUT", "120"))
HEAVY_TIMEOUT = int(os.environ.get("YQ_HEAVY_TIMEOUT", "300"))  # jadx/apktool
QUEEN_ID = "yellow"

try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo("Europe/Berlin")
except Exception:  # tzdata fehlt -> UTC
    TZ = timezone.utc


def now_iso() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")


def ensure_dirs() -> None:
    for d in (DATA_DIR, CASES_DIR, NOTES_DIR):
        d.mkdir(parents=True, exist_ok=True)
