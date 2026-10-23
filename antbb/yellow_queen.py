"""Die Gelbe Königin (Yellow Queen / Reverse-Engineering-Orchestrator).

Pendant zur offensiven und zur blauen Königin, aber auf Reverse Engineering
spezialisiert: plant und dispatcht die Yellow-Team-Soldaten entlang des
Erklärpfads (Intake → Triage → Static → Dynamic → Reconstruct → Dossier),
sammelt Findings zentral und wendet den Proof-Gate an.

Standard-Verhalten: rein lesend/non-destruktiv, kein Zielcode wird ausgeführt.
Tiefe/dynamische Schritte (`deep=True`) laufen NUR über das Oversight-Gate.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import config as config_mod
from . import llm as llm_mod
from . import netutil as net_mod
from . import router as router_mod
from . import scope as scope_mod
from . import proofgate as proofgate_mod
from .agents.base import AgentContext, AgentFinding, Task
from .agents.yellow import YELLOW_AGENTS, YELLOW_PHASES
from .active_oversight import enforce_active_oversight
from .store import Store

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: Phasen der Reverse-Engineering-Kolonie.
PHASES = YELLOW_PHASES


@dataclass
class YellowResult:
    run_id: str
    target_id: Optional[int]
    target_name: str
    findings: list[AgentFinding] = field(default_factory=list)
    phase_log: list[str] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    validation: dict = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return self.finished_at - self.started_at

    def by_severity(self) -> dict:
        return proofgate_mod.severity_counts(self.findings)

    def by_status(self) -> dict:
        return proofgate_mod.status_counts(self.findings)


class YellowQueen:
    """Orchestriert die Reverse-Engineering-Kolonie."""

    def __init__(self, store: Store, logger: Optional[logging.Logger] = None,
                 emit: Optional[Callable[[dict], None]] = None,
                 use_llm: bool = True):
        self.store = store
        self.logger = logger or logging.getLogger("antbb.yellow_queen")
        self.emit = emit
        self.llm = None
        if use_llm:
            try:
                client = llm_mod.LLMClient()
                if client.configured:
                    self.llm = client
            except Exception:
                self.llm = None

    def _agents_for_phase(self, phase: str, ctx: AgentContext,
                          only_agents: Optional[list] = None):
        agents = [cls(ctx) for cls in YELLOW_AGENTS
                  if phase in getattr(cls, "yellow_phases", ())]
        if only_agents:
            want = set(only_agents)
            agents = [a for a in agents if a.name in want]
        return agents

    async def run_colony(self, target_id: Optional[int] = None,
                         phases: tuple[str, ...] = PHASES,
                         deep: bool = False,
                         oversight_ack: Optional[bool] = None,
                         params: Optional[dict] = None) -> YellowResult:
        """Startet die Reverse-Engineering-Kolonie (Default: read-only).

        `deep=True` schaltet tiefe/dynamische Playbooks frei → hartes Oversight-Gate.
        Die Probe wird über `params['sample']` (lokaler Dateipfad) übergeben.
        """
        params = dict(params or {})
        params.setdefault("_store", self.store)
        target_name = "lokale Probe (Reverse Engineering)"
        assets: list[str] = ["localhost"]
        if target_id is not None:
            target = self.store.get_target(target_id)
            if target:
                target_name = target["name"]

        run_id = "yellow-" + uuid.uuid4().hex[:10]
        result = YellowResult(run_id=run_id, target_id=target_id,
                              target_name=target_name, started_at=time.time())

        def _emit(ev: dict) -> None:
            ev = {**ev, "run_id": run_id, "target_id": target_id, "colony": "yellow"}
            result.phase_log.append(ev.get("msg", ""))
            if self.emit:
                self.emit(ev)

        if deep:
            _log = lambda m: _emit({"ts": time.time(), "msg": m})
            enforce_active_oversight(oversight_ack,
                                     action="Yellow-Queen tiefe/dynamische RE-Analyse",
                                     log=_log)

        def _scope_check(asset: str) -> bool:
            # Yellow arbeitet an lokalen Proben – keine fremden Netzwerk-Ziele.
            return asset in ("localhost", "sample", "-", "")

        def _route(task_type, complexity=0.0):
            return router_mod.route(task_type, complexity,
                                    ask_user=router_mod.headless_ask())

        net = net_mod.NetClient(scope_check=_scope_check,
                                cfg=config_mod.scan_config(),
                                logger=self.logger, emit=_emit)
        try:
            soldier_overrides = self.store.all_soldier_overrides()
            soldier_mems = self.store.all_soldier_mems()
        except Exception:
            soldier_overrides, soldier_mems = {}, {}

        ctx = AgentContext(
            run_id=run_id, scope_check=_scope_check, logger=self.logger,
            emit=_emit, llm=self.llm, route=_route, net=net,
            active=bool(deep), fuzz=False,
            soldier_overrides=soldier_overrides, soldier_mems=soldier_mems,
        )

        ctx.log(f"👑🟡 Gelbe Königin startet RE-Kolonie (run {run_id}) für '{target_name}'.")
        ctx.log("👑🟡 Modus: " + ("TIEFE/dynamische Analyse freigegeben (Oversight)" if deep
                                   else "rein lesend/non-destruktiv (Default)") + ".")

        collected: list[AgentFinding] = []
        for phase in phases:
            agents = self._agents_for_phase(
                phase, ctx, only_agents=(params or {}).get("only_agents"))
            if not agents:
                continue
            ctx.log(f"👑🟡 Phase '{phase}': dispatche {len(agents)} Yellow-Soldat(en).")
            task = Task(phase=phase, target_id=target_id or 0,
                        target_name=target_name, assets=assets,
                        params=params, context_findings=list(collected))
            results = await asyncio.gather(*(a.run(task) for a in agents),
                                           return_exceptions=True)
            phase_findings: list[AgentFinding] = []
            for sub in results:
                if isinstance(sub, Exception):
                    ctx.log(f"👑🟡 ⚠️ Soldat-Fehler in Phase '{phase}': {sub}")
                    continue
                phase_findings.extend(sub)
            new = self._merge(collected, phase_findings)
            proofgate_mod.enforce(new, self.logger)
            if target_id is not None:
                for f in new:
                    try:
                        self.store.add_finding(
                            target_id=target_id, run_id=run_id, agent=f.agent,
                            title=f.title, category=f.category, severity=f.severity,
                            asset=f.asset, description=f.description,
                            evidence=f.evidence, dedup_key=f.key(), status=f.status,
                            false_positive=f.false_positive)
                    except Exception:
                        pass
            ctx.log(f"👑🟡 Phase '{phase}' fertig: +{len(new)} Finding(s) (gesamt {len(collected)}).")

        validation = proofgate_mod.enforce(collected, self.logger)
        result.validation = validation
        collected.sort(key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
        result.findings = collected
        result.finished_at = time.time()
        ctx.log(f"👑🟡 RE-Kolonie fertig in {result.duration:.2f}s. "
                f"Findings: {len(collected)} · Severity: {result.by_severity()}.")
        return result

    @staticmethod
    def _merge(collected: list[AgentFinding], new: list[AgentFinding]) -> list[AgentFinding]:
        seen = {f.key() for f in collected}
        added: list[AgentFinding] = []
        for f in new:
            if f.key() in seen:
                continue
            seen.add(f.key())
            collected.append(f)
            added.append(f)
        return added

    def run_colony_sync(self, target_id: Optional[int] = None,
                        phases: tuple[str, ...] = PHASES, deep: bool = False,
                        oversight_ack: Optional[bool] = None,
                        params: Optional[dict] = None) -> YellowResult:
        return asyncio.run(self.run_colony(target_id, phases, deep=deep,
                                           oversight_ack=oversight_ack, params=params))
