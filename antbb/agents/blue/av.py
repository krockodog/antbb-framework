"""Blue-Soldat: Virenscan (ClamAV) und Quarantäne.

Scannt nur übergebene, in-scope Pfade. Fehlt clamscan/clamdscan, meldet der
Lauf `unavailable` – kein clean, keine erfundenen Signaturen. Quarantäne ist
ein Move in ein kontrolliertes Verzeichnis und nur mit Oversight + Scope.
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import avscan as _av
from ... import quarantine as _q
from ...active_oversight import ACTIVE_LEGAL_NOTICE


class AvAnt(BlueAgent):
    name = "blue-av"
    specialty = "blue-malware-scanner"
    role = ("Virenscan (ClamAV) auf erlaubten Pfaden. Funde mit Pfad und "
            "SHA-256. Quarantäne nur als Move, mit Oversight und Scope.")
    blue_phases = ("assess", "defend")
    playbooks = (
        Playbook("av-scan", "defensive", False,
                 ["clamscan", "clamdscan"],
                 "Erlaubte Pfade mit ClamAV scannen. Ohne Binary: unavailable, "
                 "nie clean.",
                 tasks=["Pfade gegen Scope prüfen (default-deny)",
                        "clamscan oder clamdscan aufrufen",
                        "SHA-256 je Datei erfassen",
                        "FOUND nur aus Scanner-Ausgabe",
                        "Fehlendes Binary ehrlich melden"]),
        Playbook("av-quarantine", "defensive", True,
                 ["quarantine-move", "recheck"],
                 "Infizierte Datei in die Quarantäne verschieben (kein Löschen) "
                 "und den Originalpfad nachprüfen.",
                 tasks=["Oversight und Scope prüfen",
                        "Datei per Move quarantänisieren",
                        "Manifest mit Hash schreiben",
                        "Re-Check: GESCHLOSSEN nur mit Beleg"]),
    )

    def _paths(self, task: Task) -> list[str]:
        params = task.params or {}
        raw = list(params.get("paths") or [])
        single = params.get("path")
        if single:
            raw.append(single)
        for asset in task.assets or []:
            if isinstance(asset, str) and asset.startswith("/") and not asset.startswith("//"):
                raw.append(asset)
        out: list[str] = []
        seen: set[str] = set()
        for item in raw:
            text = str(item).strip()
            if text and text not in seen:
                seen.add(text)
                out.append(text)
        return out

    async def work(self, task: Task) -> list[AgentFinding]:
        if task.phase != self.blue_phases[0]:
            return []
        params = task.params or {}
        paths = self._paths(task)
        self.ctx.log(f"[blue-av] 🧪 Scan von {len(paths)} Pfad-Angabe(n).")
        report = _av.scan_paths(paths, scope_check=self.ctx.scope_check)
        findings: list[AgentFinding] = [AgentFinding(
            agent=self.name,
            title=f"AV-Scan: {report.status} ({report.engine or 'kein Engine'})",
            category="blue-av-unavailable" if report.status == "unavailable"
            else ("blue-av-summary" if report.status != "denied" else "blue-av-denied"),
            severity="info", asset="localhost",
            description=report.reason,
            evidence={
                "status": report.status, "engine": report.engine,
                "clean": report.clean, "infected_count": report.infected_count,
                "scanned_count": report.scanned_count,
                "denied_count": report.denied_count,
                "files": [f.to_dict() for f in report.files[:50]],
            },
            status="REFERENZ",
            dedup_key="blue-av-summary",
        )]
        infected = [f for f in report.files if f.verdict == "infected"]
        for item in infected:
            findings.append(AgentFinding(
                agent=self.name,
                title=f"Malware: {item.signature or 'FOUND'} in {item.path}",
                category="blue-av-infection", severity="high", asset=item.path,
                description=f"ClamAV FOUND. SHA-256 {item.sha256}.",
                evidence=item.to_dict(),
                status="BESTÄTIGT(PASSIV)",
                dedup_key=f"blue-av:{item.sha256}:{item.path}",
            ))
        self.ctx.log(f"[blue-av] Status {report.status}, infiziert={len(infected)}.")

        want = bool(params.get("apply_quarantine") or params.get("apply_protect"))
        if not infected or not want:
            return findings
        if not self.active_allowed():
            self.ctx.log("[blue-av] Quarantäne nicht ausgeführt (Oversight fehlt).")
            findings.append(AgentFinding(
                agent=self.name, title="Quarantäne nicht ausgeführt",
                category="blue-av-denied", severity="info", asset="localhost",
                description="BLOCKIERT (default-deny): Oversight fehlt. Dateien bleiben liegen.",
                evidence={"apply_quarantine": True, "moved": 0},
                status="REFERENZ", dedup_key="blue-av-quarantine-denied",
            ))
            return findings
        if not self.playbook_enabled("av-quarantine"):
            return findings
        self.ctx.log(f"⚖ {ACTIVE_LEGAL_NOTICE}")
        root = params.get("quarantine_root") or None
        for item in infected:
            moved = _q.quarantine_move(
                item.path, active=True, scope_check=self.ctx.scope_check, root=root,
            )
            recheck = (moved.evidence or {}).get("recheck") or {}
            closed = bool(moved.closed)
            findings.append(AgentFinding(
                agent=self.name,
                title=("[GESCHLOSSEN] " if closed else "[QUARANTÄNE] ") + item.path,
                category="blue-remediation-verified" if closed else "blue-av-infection",
                severity="info" if closed else "high",
                asset=item.path,
                description=moved.reason,
                evidence={
                    "path": item.path, "sha256": item.sha256,
                    "signature": item.signature,
                    "action": moved.to_dict(), "recheck": recheck,
                    "before": recheck.get("before"), "after": recheck.get("after"),
                    "closed": closed,
                },
                status="GESCHLOSSEN" if closed else "ZU BESTÄTIGEN",
                dedup_key=f"blue-av-quarantine:{item.sha256}",
            ))
        return findings
