"""Blue-Soldat: Incident-Response-Basics (Playbooks + Checklisten)."""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import quarantine as _q
from ...active_oversight import ACTIVE_LEGAL_NOTICE

IR_PLAYBOOKS = [
    {"id": "ir-triage", "title": "Triage & Severity",
     "steps": ["Signal klassifizieren", "Business-Impact schätzen",
               "Severity (SEV1–4) setzen", "On-Call informieren"],
     "severity": "info"},
    {"id": "ir-contain", "title": "Containment",
     "steps": ["Betroffene Assets isolieren", "Credentials rotieren (geplant)",
               "Honeypot-Umleitung prüfen", "Firewall-Regel temporär setzen"],
     "severity": "medium"},
    {"id": "ir-eradicate", "title": "Eradication",
     "steps": ["Root-Cause eingrenzen", "Malware/Backdoor entfernen (geplant)",
               "Patches einspielen", "Persistenz prüfen"],
     "severity": "medium"},
    {"id": "ir-recover", "title": "Recovery & Lessons",
     "steps": ["Services kontrolliert wiederherstellen",
               "Monitoring schärfen", "Post-Incident-Report",
               "Playbook-Lücken schließen"],
     "severity": "info"},
    {"id": "ir-comms", "title": "Kommunikation",
     "steps": ["Stakeholder-Liste", "Status-Update-Takt",
               "Externe Meldepflichten prüfen", "Keine Secrets in Comms"],
     "severity": "info"},
]


class IncidentAnt(BlueAgent):
    name = "blue-incident"
    specialty = "blue-incident-responder"
    role = ("Incident-Response-Basics: Triage, Containment, Eradication, "
            "Recovery und Kommunikation als ausführbare Playbooks.")
    blue_phases = ("defend", "remediate", "verify")
    playbooks = (
        Playbook("ir-triage", "defensive", False,
                 ["severity-matrix", "on-call"],
                 "Incident triageen und Severity setzen.",
                 tasks=IR_PLAYBOOKS[0]["steps"]),
        Playbook("ir-containment", "defensive", True,
                 ["isolate-asset", "temp-firewall"],
                 "Containment-Schritte – aktive Isolation nur mit Oversight.",
                 tasks=IR_PLAYBOOKS[1]["steps"]),
        Playbook("ir-eradication-recovery", "defensive", True,
                 ["eradicate", "recover", "lessons-learned"],
                 "Eradication + Recovery + Lessons-Learned.",
                 tasks=IR_PLAYBOOKS[2]["steps"] + IR_PLAYBOOKS[3]["steps"]),
        Playbook("ir-comms", "defensive", False,
                 ["stakeholder-comms"],
                 "Kommunikations-Checkliste ohne Secrets.",
                 tasks=IR_PLAYBOOKS[4]["steps"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log(f"[blue-incident] 🚨 {len(IR_PLAYBOOKS)} IR-Playbooks bereit.")
        for pb in IR_PLAYBOOKS:
            findings.append(AgentFinding(
                agent=self.name, title=f"IR: {pb['title']}",
                category="blue-incident-playbook", severity=pb["severity"],
                asset="monitoring",
                description=" → ".join(pb["steps"]),
                evidence={"playbook_id": pb["id"], "steps": pb["steps"],
                          "oversight_for_active": pb["id"] in ("ir-contain", "ir-eradicate")},
                status="REFERENZ",
                dedup_key=f"blue-incident:{pb['id']}",
            ))
        params = task.params or {}
        want = bool(params.get("apply_contain") or params.get("apply_protect")
                    or params.get("apply_quarantine"))
        if task.phase == "verify":
            findings.extend(self._reverify(task))
            return findings
        if task.phase != "defend" or not want:
            return findings
        paths = [str(p) for p in (params.get("quarantine_paths") or []) if str(p).strip()]
        sources = [str(s) for s in (params.get("isolate_sources") or []) if str(s).strip()]
        if not self.active_allowed():
            self.ctx.log("[blue-incident] Containment nicht ausgeführt (Oversight fehlt).")
            findings.append(self._action_finding(
                "Containment blockiert", "denied",
                "BLOCKIERT (default-deny): Oversight fehlt. Nichts isoliert, nichts verschoben.",
                {"paths": paths, "sources": sources, "closed": False},
            ))
            return findings
        if not paths and not sources:
            findings.append(self._action_finding(
                "Containment ohne Ziele", "skipped",
                "Apply-Flag gesetzt, aber keine quarantine_paths oder isolate_sources.",
                {"closed": False},
            ))
            return findings
        self.ctx.log(f"⚖ {ACTIVE_LEGAL_NOTICE}")
        root = params.get("quarantine_root") or None
        runner = params.get("isolate_runner")
        for path in paths:
            moved = _q.quarantine_move(
                path, active=True, scope_check=self.ctx.scope_check, root=root,
            )
            recheck = (moved.evidence or {}).get("recheck") or {}
            findings.append(self._action_finding(
                ("[GESCHLOSSEN] " if moved.closed else "[QUARANTÄNE] ") + path,
                "GESCHLOSSEN" if moved.closed else moved.status,
                moved.reason,
                {"path": path, "action": moved.to_dict(), "recheck": recheck,
                 "before": recheck.get("before"), "after": recheck.get("after"),
                 "closed": moved.closed, "sha256": (moved.evidence.get("manifest") or {}).get("sha256")
                 if isinstance(moved.evidence, dict) else ""},
                closed=bool(moved.closed),
            ))
        for source in sources:
            iso = _q.isolate_source(
                source, active=True, scope_check=self.ctx.scope_check,
                runner=runner if callable(runner) else None,
            )
            findings.append(self._action_finding(
                ("[GESCHLOSSEN] " if iso.closed else "[ISOLATION] ") + source,
                "GESCHLOSSEN" if iso.closed else iso.status,
                iso.reason,
                {"source": source, "action": iso.to_dict(),
                 "before": (iso.evidence or {}).get("before"),
                 "after": (iso.evidence or {}).get("after"),
                 "closed": iso.closed},
                closed=bool(iso.closed),
            ))
        return findings

    def _reverify(self, task: Task) -> list[AgentFinding]:
        params = task.params or {}
        paths = [str(p) for p in (params.get("quarantine_paths") or []) if str(p).strip()]
        out: list[AgentFinding] = []
        root = params.get("quarantine_root") or None
        for path in paths:
            rec = _q.recheck_original(path, scope_check=self.ctx.scope_check, root=root)
            closed = bool(rec.get("closed"))
            out.append(self._action_finding(
                ("[GESCHLOSSEN] " if closed else "[RE-CHECK] ") + path,
                "GESCHLOSSEN" if closed else str(rec.get("status") or "open"),
                rec.get("reason") or "",
                {"path": path, "recheck": rec, "before": rec.get("before"),
                 "after": rec.get("after"), "closed": closed},
                closed=closed,
            ))
        return out

    def _action_finding(self, title: str, label: str, description: str,
                        evidence: dict, closed: bool = False) -> AgentFinding:
        return AgentFinding(
            agent=self.name, title=title,
            category="blue-remediation-verified" if closed else "blue-incident-action",
            severity="info", asset=str(evidence.get("path") or evidence.get("source") or "monitoring"),
            description=description, evidence=evidence,
            status="GESCHLOSSEN" if closed else ("REFERENZ" if label == "denied" else "ZU BESTÄTIGEN"),
            dedup_key=f"blue-incident-action:{title}",
        )
