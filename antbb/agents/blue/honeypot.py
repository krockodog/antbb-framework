"""Blue-Soldat: Honeypot/Decoy.

Rezepte bleiben lesend. Mit Oversight startet `honeypot-deploy` einen
low-interaction Canary auf 127.0.0.1 (HTTP-Text und SSH-Banner). Cowrie wird
nicht installiert. Ohne Oversight oder Scope: ehrlicher Deny, kein Socket.
"""
from __future__ import annotations

from .base import BlueAgent, AgentFinding, Playbook, Task
from ... import honeypot as _hp
from ...active_oversight import ACTIVE_LEGAL_NOTICE

HONEYPOT_RECIPES = [
    {"id": "ssh-decoy", "title": "SSH-Decoy (low-interaction)",
     "desc": "Fake-SSH auf unüblichem Port, der nur Verbindungs-/Login-Versuche "
             "protokolliert (z.B. cowrie im low-interaction-Modus, isoliert).",
     "safety": "In isoliertem Netz/Container, keine echten Credentials, Logs lokal."},
    {"id": "http-canary", "title": "HTTP-Canary-Endpoint",
     "desc": "Unverlinkter Pfad/Token, dessen Abruf einen Alarm auslöst "
             "(Canarytoken-Prinzip).",
     "safety": "Kein echter Dienst dahinter; nur Zugriffs-Logging."},
    {"id": "decoy-file", "title": "Decoy-Dokument (Canary)",
     "desc": "Köder-Datei mit eingebettetem Canary, die beim Öffnen/Exfil meldet.",
     "safety": "Enthält keine echten Daten; rein als Tripwire."},
]


class HoneypotAnt(BlueAgent):
    name = "blue-honeypot"
    specialty = "blue-honeypot-keeper"
    role = ("Honeypots/Decoys: Rezepte lesend. Deploy startet einen Loopback-"
            "Canary nur mit Oversight und Scope, sonst ehrlicher Fehlschlag.")
    blue_phases = ("defend",)
    playbooks = (
        Playbook("honeypot-recipes", "defensive", False,
                 ["ssh-decoy", "http-canary", "decoy-file"],
                 "Sichere Honeypot-/Decoy-Rezepte (Doku) bereitstellen."),
        Playbook("honeypot-deploy", "defensive", True,
                 ["start-decoy"],
                 "Loopback-Canary (HTTP/SSH-Banner) starten – NUR mit Oversight "
                 "und Scope. Cowrie wird nicht automatisch installiert.",
                 tasks=["Oversight und Scope prüfen",
                        "HTTP-Canary auf 127.0.0.1 starten",
                        "SSH-Banner-Canary starten",
                        "Versuche lokal protokollieren",
                        "Bei Bind-Fehler ehrlich fehlschlagen"]),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        self.ctx.log(f"[blue-honeypot] 🍯 {len(HONEYPOT_RECIPES)} Decoy-Rezept(e) bereitgestellt.")
        for r in HONEYPOT_RECIPES:
            findings.append(AgentFinding(
                agent=self.name, title=f"Honeypot: {r['title']}",
                category="blue-honeypot-recipe", severity="info", asset="decoy",
                description=f"{r['desc']} · Sicherheit: {r['safety']}",
                evidence={"recipe_id": r["id"], "safety": r["safety"]},
                status="REFERENZ", dedup_key=f"blue-honeypot:{r['id']}"))
        params = task.params or {}
        if not self.playbook_enabled("honeypot-deploy"):
            return findings
        if not self.active_allowed():
            self.ctx.log("[blue-honeypot] Deploy nicht gestartet (Oversight fehlt, default-deny).")
            findings.append(AgentFinding(
                agent=self.name, title="Canary nicht gestartet",
                category="blue-honeypot-deploy", severity="info", asset="decoy",
                description="BLOCKIERT (default-deny): ohne Oversight wird kein Listener geöffnet.",
                evidence={"applied": False, "status": "denied", "cowrie": "not-started"},
                status="REFERENZ", dedup_key="blue-honeypot-deploy",
            ))
            return findings
        self.ctx.log(f"⚖ {ACTIVE_LEGAL_NOTICE}")
        dep = _hp.deploy_canary(
            active=True, scope_check=self.ctx.scope_check,
            http_port=int(params.get("canary_http_port") or 8089),
            ssh_port=int(params.get("canary_ssh_port") or 2222),
            log_dir=params.get("canary_log_dir") or None,
        )
        self.ctx.log(f"[blue-honeypot] Deploy {dep.status}: {dep.reason}")
        findings.append(AgentFinding(
            agent=self.name,
            title=f"Canary {dep.status}",
            category="blue-honeypot-deploy", severity="info", asset="decoy",
            description=dep.reason,
            evidence=dep.to_dict(),
            status="BESTÄTIGT(PASSIV)" if dep.applied else "ZU BESTÄTIGEN",
            dedup_key="blue-honeypot-deploy",
        ))
        return findings
