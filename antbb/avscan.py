"""ClamAV-Adapter für blue-av.

Scannt nur Pfade, die der Scope-Check erlaubt (default-deny). Fehlen
`clamscan` und `clamdscan`, ist der Status `unavailable` – niemals clean.
Infizierte Dateien entstehen nur aus echten FOUND-Zeilen. Jedes Datei-Ergebnis
trägt Pfad und SHA-256.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

MAX_FILES = 2000


@dataclass
class CmdResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class AvFileResult:
    path: str
    sha256: str = ""
    verdict: str = "not_scanned"   # clean | infected | error | unknown | not_scanned | skipped
    signature: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AvReport:
    status: str                     # unavailable | completed | denied | empty | error | partial
    engine: str = ""
    reason: str = ""
    files: list[AvFileResult] = field(default_factory=list)
    infected_count: int = 0
    scanned_count: int = 0
    denied_count: int = 0
    raw_excerpt: str = ""

    @property
    def clean(self) -> bool:
        """True nur nach abgeschlossenem Scan, jede gescannte Datei OK.

        Übersprungene (out-of-scope) Einträge zählen nicht als clean und
        auch nicht als Fund. `unavailable` ist nie clean.
        """
        if self.status != "completed" or self.infected_count:
            return False
        scanned = [f for f in self.files if f.verdict != "skipped"]
        return bool(scanned) and all(f.verdict == "clean" for f in scanned)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["clean"] = self.clean
        return d


def which_engine() -> Optional[str]:
    """Bevorzugt clamscan (Einzelschnelllauf). Sonst clamdscan. Sonst None."""
    if shutil.which("clamscan"):
        return "clamscan"
    if shutil.which("clamdscan"):
        return "clamdscan"
    return None


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_clam_output(stdout: str, stderr: str = "", returncode: int = 0) -> list[dict]:
    """Parst clamscan/clamdscan-Zeilen. Summary erzeugt keine Funde.

    FOUND → infected, OK → clean, ERROR → error. Alles andere bleibt
    `unknown` (kein stilles clean, keine erfundene Signatur).
    """
    del stderr, returncode  # Signatur nur aus der Zeile, nicht aus dem Exitcode
    rows: list[dict] = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("---") or "SCAN SUMMARY" in s:
            break
        path, sep, rest = s.rpartition(": ")
        if not sep or not path:
            continue
        rest_u = rest.strip()
        if rest_u == "OK":
            rows.append({"path": path, "verdict": "clean", "signature": "", "detail": ""})
        elif rest_u.endswith(" FOUND"):
            sig = rest_u[: -len(" FOUND")].strip()
            rows.append({"path": path, "verdict": "infected", "signature": sig, "detail": rest_u})
        elif "ERROR" in rest_u.upper():
            rows.append({"path": path, "verdict": "error", "signature": "", "detail": rest_u})
        else:
            rows.append({"path": path, "verdict": "unknown", "signature": "", "detail": rest_u})
    return rows


def _in_scope(path: str, scope_check: Callable[[str], bool]) -> bool:
    try:
        return bool(scope_check(path))
    except Exception:
        return False


def _collect(paths: list[str], scope_check: Callable[[str], bool]
             ) -> tuple[list[str], list[str], bool]:
    """Liefert (erlaubt, verweigert, limit_erreicht). Folgt keinen Symlinks."""
    allowed: list[str] = []
    denied: list[str] = []
    seen: set[str] = set()
    truncated = False

    def add_file(fp: str) -> bool:
        nonlocal truncated
        if fp in seen:
            return False
        if len(allowed) >= MAX_FILES:
            truncated = True
            return True
        seen.add(fp)
        allowed.append(fp)
        return False

    for raw in paths:
        abs_p = os.path.abspath(raw)
        if os.path.islink(abs_p):
            real = os.path.realpath(abs_p)
            if not (_in_scope(abs_p, scope_check) and _in_scope(real, scope_check)):
                denied.append(abs_p)
                continue
            abs_p = real
        if not _in_scope(abs_p, scope_check):
            denied.append(abs_p)
            continue
        if os.path.isdir(abs_p):
            for dirpath, dirnames, filenames in os.walk(abs_p, followlinks=False):
                kept = []
                for d in dirnames:
                    dp = os.path.join(dirpath, d)
                    if os.path.islink(dp) or not _in_scope(dp, scope_check):
                        if not os.path.islink(dp):
                            denied.append(dp)
                        continue
                    kept.append(d)
                dirnames[:] = kept
                for fn in filenames:
                    fp = os.path.join(dirpath, fn)
                    if os.path.islink(fp) or not os.path.isfile(fp):
                        continue
                    if not _in_scope(fp, scope_check):
                        denied.append(fp)
                        continue
                    if add_file(fp):
                        return allowed, denied, True
            continue
        if os.path.isfile(abs_p):
            if add_file(abs_p):
                return allowed, denied, True
        else:
            denied.append(abs_p)
    return allowed, denied, truncated


def _identity(path: str, verdict: str, detail: str = "") -> AvFileResult:
    digest = ""
    if os.path.isfile(path) and not os.path.islink(path):
        try:
            digest = file_sha256(path)
        except OSError as exc:
            return AvFileResult(path=path, verdict="error", detail=type(exc).__name__)
    return AvFileResult(path=path, sha256=digest, verdict=verdict, detail=detail)


def _default_runner(cmd: list[str]) -> CmdResult:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
    return CmdResult(proc.returncode, proc.stdout or "", proc.stderr or "")


def _engine_cmd(engine: str, files: list[str]) -> list[str]:
    # --no-summary hält die Parser-Grenze stabil; Dateien stehen explizit
    # auf der Kommandozeile (kein stilles Verzeichnis-Rekursion-Follow).
    return [engine, "--no-summary", *files]


def scan_paths(paths, *, scope_check: Optional[Callable[[str], bool]] = None,
               runner: Optional[Callable[[list[str]], CmdResult]] = None,
               engine: Optional[str] = None) -> AvReport:
    """Scannt `paths` nur in-scope. `runner` ist die Test-Naht für die Parse-Logik.

    Ohne `runner` wird das echte Binary aufgerufen. Fehlt es, Status
    `unavailable` – die Dateien bleiben `not_scanned`, nie infected/clean.
    """
    if scope_check is None:
        return AvReport(status="denied", reason="Kein Scope-Check (default-deny). Kein Scan.")
    requested = [str(p) for p in (paths or []) if str(p).strip()]
    if not requested:
        return AvReport(
            status="empty",
            reason="Keine Pfade übergeben. Kein Ganzplatten-Scan (default-deny).",
        )
    allowed, denied, truncated = _collect(requested, scope_check)
    denied_files = [
        AvFileResult(path=p, verdict="skipped", detail="out-of-scope oder nicht lesbar")
        for p in denied[:50]
    ]
    if not allowed:
        return AvReport(
            status="denied", engine=engine or which_engine() or "",
            reason="Alle Pfade out-of-scope oder keine reguläre Datei (default-deny).",
            files=denied_files, denied_count=len(denied),
        )

    resolved = engine if engine else which_engine()
    if runner is None and not resolved:
        files = [_identity(p, "not_scanned", "Scanner fehlt") for p in allowed]
        files.extend(denied_files)
        return AvReport(
            status="unavailable", engine="",
            reason=("clamscan/clamdscan nicht installiert. "
                    "Kein clean-Befund, keine erfundenen Signaturen."),
            files=files, denied_count=len(denied),
            scanned_count=0, infected_count=0,
        )
    if not resolved:
        return AvReport(
            status="unavailable",
            reason="Kein Engine-Name und kein clamscan/clamdscan. Nichts gescannt.",
            files=[_identity(p, "not_scanned") for p in allowed],
            denied_count=len(denied),
        )

    run = runner or _default_runner
    files = [_identity(p, "unknown") for p in allowed]
    excerpts: list[str] = []
    parsed: list[dict] = []
    worst = 0
    try:
        for i in range(0, len(allowed), 80):
            chunk = allowed[i:i + 80]
            result = run(_engine_cmd(resolved, chunk))
            if not isinstance(result, CmdResult):
                result = CmdResult(
                    int(getattr(result, "returncode", 2)),
                    str(getattr(result, "stdout", "") or ""),
                    str(getattr(result, "stderr", "") or ""),
                )
            worst = max(worst, result.returncode)
            excerpts.append((result.stdout or "")[:1500])
            parsed.extend(parse_clam_output(result.stdout, result.stderr, result.returncode))
    except Exception as exc:
        return AvReport(
            status="error", engine=resolved,
            reason=f"Scanner-Aufruf fehlgeschlagen: {type(exc).__name__}",
            files=files, denied_count=len(denied), scanned_count=0,
        )

    by_path = {row["path"]: row for row in parsed}
    for item in files:
        row = by_path.get(item.path) or by_path.get(os.path.abspath(item.path))
        if row is None and len(files) == 1 and len(parsed) == 1:
            row = parsed[0]
        if not row:
            item.verdict = "error" if worst not in (0, 1) else "unknown"
            item.detail = "Scanner hat die Datei nicht einzeln bestätigt."
            continue
        item.verdict = row["verdict"]
        item.signature = row.get("signature") or ""
        item.detail = row.get("detail") or ""

    infected = sum(1 for f in files if f.verdict == "infected")
    if worst not in (0, 1) and infected == 0:
        status = "error"
        reason = f"{resolved} endete mit Code {worst}. Nicht als clean gewertet."
    elif truncated:
        status = "partial"
        reason = f"Scan auf {MAX_FILES} Dateien begrenzt. Rest nicht behauptet."
    else:
        status = "completed"
        reason = f"{resolved}: {infected} infizierte Datei(en) von {len(files)}."
    files.extend(denied_files)
    return AvReport(
        status=status, engine=resolved, reason=reason, files=files,
        infected_count=infected, scanned_count=len(allowed),
        denied_count=len(denied), raw_excerpt="\n".join(excerpts)[:2000],
    )


def recheck_path(path: str, *, scope_check: Optional[Callable[[str], bool]],
                 runner: Optional[Callable[[list[str]], CmdResult]] = None,
                 engine: Optional[str] = None) -> dict:
    """Liest einen einzelnen Pfad erneut. Closed nur bei verdict clean.

    Fehlende Datei allein ist kein clean (das entscheidet die Quarantäne
    über das Manifest). Fehlender Scanner → nicht geschlossen.
    """
    abs_p = os.path.abspath(path) if path else ""
    before_present = bool(abs_p and os.path.isfile(abs_p) and not os.path.islink(abs_p))
    if not abs_p or not before_present:
        return {
            "closed": False, "status": "absent",
            "reason": "Datei liegt nicht (mehr) am Pfad. Ohne Quarantäne-Manifest kein Abschluss.",
            "before": {"path": abs_p, "present": before_present},
            "after": {"path": abs_p, "present": False},
        }
    report = scan_paths([abs_p], scope_check=scope_check, runner=runner, engine=engine)
    file_row = next((f for f in report.files if f.path == abs_p), None)
    closed = bool(report.clean and file_row and file_row.verdict == "clean")
    return {
        "closed": closed,
        "status": "GESCHLOSSEN" if closed else report.status,
        "reason": report.reason,
        "before": {"path": abs_p, "present": True, "sha256": file_row.sha256 if file_row else ""},
        "after": {
            "path": abs_p, "present": True,
            "verdict": file_row.verdict if file_row else report.status,
            "sha256": file_row.sha256 if file_row else "",
            "signature": file_row.signature if file_row else "",
            "clean": report.clean,
        },
        "engine": report.engine,
    }
