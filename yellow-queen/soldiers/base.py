"""Soldaten-Basis: echte CLIs wenn vorhanden (nie das Sample ausführen), sonst Python-Fallback."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import config
from ..doctor import find
from ..redact import redact


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


@dataclass
class SoldierResult:
    name: str
    skill: str
    title_de: str
    status: str = "ok"  # ok | partial | skipped
    tools_used: list[str] = field(default_factory=list)
    tools_missing: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    warum: str = ""
    fund: str = ""
    next: list[str] = field(default_factory=list)
    summary_de: str = ""


@dataclass
class Ctx:
    sample: Path
    evidence_dir: Path
    classification: dict[str, Any]
    dynamic: str = "no"


def run_cli(ctx: Ctx, res: SoldierResult, tool_id: str, candidates: list[str], args: list[str],
            out_name: str, timeout: int | None = None) -> str | None:
    """Ruft ein Tool auf (ohne Shell). Ausgabe wird geschwärzt in evidence/<out_name> gespeichert."""
    exe = find(candidates)
    if not exe:
        res.tools_missing.append(tool_id)
        return None
    try:
        r = subprocess.run([exe, *args], capture_output=True, timeout=timeout or config.TOOL_TIMEOUT,
                           stdin=subprocess.DEVNULL, cwd=str(ctx.evidence_dir))
        text = (r.stdout.decode("utf-8", "replace") + (("\n[stderr]\n" + r.stderr.decode("utf-8", "replace")) if r.stderr else ""))
    except subprocess.TimeoutExpired:
        text = f"[Timeout nach {timeout or config.TOOL_TIMEOUT}s]"
        res.status = "partial"
    except OSError as e:
        text = f"[Start fehlgeschlagen: {e}]"
        res.status = "partial"
    text = redact(ANSI.sub("", text))[:400_000]
    (ctx.evidence_dir / out_name).write_text(text, encoding="utf-8")
    res.tools_used.append(tool_id)
    res.evidence.append(out_name)
    return text


def py_strings(data: bytes, minlen: int = 6, limit: int = 5000) -> list[str]:
    out = [m.group().decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data)]
    return out[:limit]


def hexdump(data: bytes, n: int = 256) -> str:
    lines = []
    for i in range(0, min(len(data), n), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hx:<47}  {asc}")
    return "\n".join(lines)


def first_lines(text: str | None, n: int = 12) -> list[str]:
    return [ln for ln in (text or "").splitlines() if ln.strip()][:n]


def redact_tree(root: Path, exts=(".java", ".xml", ".smali", ".txt", ".json", ".properties", ".kt", ".yml", ".yaml", ".js", ".html")) -> int:
    """Schwärzt Secrets in entpackten/decompilierten Textdateien (in place)."""
    n = 0
    if not root.exists():
        return 0
    for f in root.rglob("*"):
        try:
            if f.is_file() and f.suffix.lower() in exts and f.stat().st_size < 2_000_000:
                t = f.read_text("utf-8", "ignore")
                r = redact(t)
                if r != t:
                    f.write_text(r, encoding="utf-8")
                    n += 1
        except OSError:
            pass
    return n
