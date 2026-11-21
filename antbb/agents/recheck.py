"""Recheck-Ameise: eng begrenzter Re-Check GENAU EINES Red-Befunds (ABPM-13 A).

Läuft nur in der eigenen Phase ``"recheck"`` und nur, wenn die Brücke
(``bridge.remediate_and_recheck``) eine Spezifikation aus
``remediation.red_recheck_spec`` in ``task.params["recheck"]`` mitgibt. Sie ist
bewusst KEIN regulärer Soldat (nicht in ``WORKER_AGENTS``): normale Scans und
die Capability-Registry bleiben unverändert.

Leitplanken (unverändert wirksam, nichts davon wird hier ersetzt):
  * Der Lauf startet über ``Service.run_scan`` -> Archiv-/Hosted-Gates,
    mode_policy, Human-Oversight-Gate für aktive Läufe.
  * Scope default-deny: Asset-Check hier, zusätzlich in ``ctx.net`` (HTTP/TLS)
    und in ``KaliAdapter.run`` (externe Tools). Offensive Tools laufen nur bei
    freigeschaltetem ``ctx.active``.
  * Rein lesend, ein Ziel, ein Befund: dieselbe Erkennung bzw. dasselbe
    Tool/Template, dasselbe Asset. Kein Auto-Apply.

Ergebnis je Lauf: genau ein Meta-Fund ``category="recheck-result"`` mit
``evidence.reproduced`` = True (Befund besteht weiter) | False (sauber geprüft,
nicht mehr vorhanden) | None (nicht belastbar prüfbar: Tool fehlt, nicht
freigeschaltet, Netzfehler, Parse-Fallback, mehrdeutig). Besteht der Befund
weiter, wird er zusätzlich mit dem ORIGINAL-dedup_key zurückgegeben.
"""
from __future__ import annotations

from typing import Optional

from .base import AntAgent, AgentFinding, Task, Playbook, STATUS_REFERENCE, STATUS_TO_CONFIRM
from .infra import _WEAK_PROTOCOLS
from .scanning import _LISTING_SIGS
from .verify import _ARTIFACTS
from ..netutil import host_of, build_catchall_baseline
from .. import remediation as rem

RECHECK_PHASE = "recheck"
RECHECK_CATEGORY = "recheck-result"


class RecheckAnt(AntAgent):
    name = "recheck"
    role = "Enger Re-Check eines einzelnen Red-Befunds (Brücke)"
    specialty = "recheck"
    phases = (RECHECK_PHASE,)
    playbooks = (
        Playbook("befund-recheck", "defensive", False,
                 ["http-get", "tls-info", "sslscan", "nikto", "nuclei", "wpscan",
                  "whatweb", "trufflehog"],
                 "Prüft genau einen Befund erneut (gleiche Erkennung, gleiches Asset)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        spec = (task.params or {}).get("recheck")
        if not isinstance(spec, dict) or spec.get("kind") not in rem.RED_KINDS:
            self.ctx.log("[recheck] keine gültige Re-Check-Spezifikation – nichts zu tun.")
            return []
        scope_asset = self._scope_asset(spec)
        if not scope_asset or not self._in_scope(scope_asset):
            return [self._meta(spec, None, {"reason": "out_of_scope", "asset": scope_asset})]
        kind = spec["kind"]
        handler = {
            rem.RED_KIND_HEADER: self._header,
            rem.RED_KIND_TLS: self._tls,
            rem.RED_KIND_PATH: self._path,
            rem.RED_KIND_NIKTO: self._nikto,
            rem.RED_KIND_VERSION: self._version,
            rem.RED_KIND_SECRET: self._secret,
            rem.RED_KIND_NUCLEI: self._nuclei,
        }[kind]
        reproduced, detail, again = await handler(spec)
        self.ctx.log(f"[recheck] {kind} {spec.get('dedup_key') or spec.get('asset')}: "
                     f"reproduced={reproduced} ({detail.get('reason', '')})")
        return list(again) + [self._meta(spec, reproduced, detail)]

    # ------------------------------------------------------------------ Helfer
    @staticmethod
    def _scope_asset(spec: dict) -> str:
        if spec["kind"] == rem.RED_KIND_SECRET:
            return spec.get("location") or ""
        if spec["kind"] == rem.RED_KIND_NUCLEI:
            return spec.get("matched_at") or spec.get("asset") or ""
        return spec.get("url") or spec.get("asset") or ""

    def _meta(self, spec: dict, reproduced: Optional[bool], detail: dict) -> AgentFinding:
        key = spec.get("dedup_key") or f"{spec.get('category')}:{spec.get('asset')}"
        verdict = {True: "besteht weiter", False: "nicht mehr vorhanden",
                   None: "nicht belastbar prüfbar"}[reproduced]
        return AgentFinding(
            agent=self.name, title=f"Re-Check ({spec['kind']}): {verdict}",
            category=RECHECK_CATEGORY, severity="info", asset=spec.get("asset", ""),
            description=f"Enger Re-Check von '{spec.get('title') or key}': {verdict}.",
            evidence={"recheck_of": key, "recheck_kind": spec["kind"],
                      "reproduced": reproduced, "detail": detail,
                      "detector": spec.get("detector") or spec.get("tool") or ""},
            status=STATUS_REFERENCE,
            dedup_key=f"recheck:{self.ctx.run_id}:{key}",
        )

    def _again(self, spec: dict, evidence: dict, description: str) -> AgentFinding:
        """Befund besteht weiter: mit ORIGINAL-dedup_key (Abgleich in der Brücke)."""
        return AgentFinding(
            agent=self.name, title=spec.get("title") or spec["kind"],
            category=spec.get("category", ""), severity="info", asset=spec.get("asset", ""),
            description=description, evidence={**evidence, "recheck": True},
            status=STATUS_TO_CONFIRM, dedup_key=spec.get("dedup_key") or "",
        )

    def _kali(self):
        from ..tools.kali import KaliAdapter
        return KaliAdapter(self.ctx)

    @staticmethod
    def _tool_clean(ka) -> tuple[bool, dict]:
        """Lief das Tool wirklich und war die Ausgabe sauber lesbar?"""
        results = list(getattr(ka, "tool_results", []) or [])
        if not results:
            return False, {"reason": "tool_not_run"}
        last = results[-1]
        if not last.available:
            return False, {"reason": "tool_missing", "error": last.error}
        if not last.ok:
            return False, {"reason": "tool_not_ok", "error": last.error,
                           "timed_out": last.timed_out, "in_scope": last.in_scope}
        if ka.parse_events:
            return False, {"reason": "parse_degraded", "parse_events": ka.parse_events[:5]}
        return True, {}

    # ------------------------------------------------------------- Erkennungen
    async def _header(self, spec):
        net = self.ctx.net
        if net is None:
            return None, {"reason": "no_net_client"}, []
        resp = await net.http_get(spec["url"])
        if resp is None:
            return None, {"reason": "request_failed"}, []
        name = spec["header"]
        present = name in resp.headers
        detail = {"reason": "header_present" if present else "header_missing",
                  "http_status": resp.status_code, "header": name}
        if present:
            return False, detail, []
        return True, detail, [self._again(spec, {"missing_header": name},
                                          f"Security-Header '{name}' fehlt weiterhin.")]

    async def _tls(self, spec):
        host = host_of(spec["asset"]) or spec["asset"]
        if spec.get("detector") == "kali.sslscan":
            ka = self._kali()
            found = await ka.sslscan(host, agent=self.name)
            clean, why = self._tool_clean(ka)
            weak = sorted({p for f in found for p in (f.evidence.get("weak_protocols") or [])})
            if weak:
                return True, {"reason": "weak_protocols", "weak_protocols": weak}, [
                    self._again(spec, {"weak_protocols": weak, "tool": "sslscan"},
                                f"Schwache TLS-Protokolle weiterhin aktiv: {', '.join(weak)}.")]
            if not clean:
                return None, why, []
            return False, {"reason": "no_weak_protocols", "tool": "sslscan"}, []
        net = self.ctx.net
        if net is None:
            return None, {"reason": "no_net_client"}, []
        info = await net.tls_info(host, 443)
        if not info:
            return None, {"reason": "tls_info_unavailable"}, []
        proto = info.get("protocol") or ""
        if proto in _WEAK_PROTOCOLS:
            return True, {"reason": "weak_protocol", "protocol": proto}, [
                self._again(spec, {"protocol": proto},
                            f"Server handelt weiterhin schwaches TLS-Protokoll {proto} aus.")]
        if not proto:
            return None, {"reason": "protocol_unknown"}, []
        return False, {"reason": "strong_protocol", "protocol": proto}, []

    async def _path(self, spec):
        net = self.ctx.net
        if net is None:
            return None, {"reason": "no_net_client"}, []
        url = spec["url"]
        resp = await net.http_get(url)
        if resp is None:
            return None, {"reason": "request_failed"}, []
        status = resp.status_code
        orig = int(spec.get("orig_http_status") or 200)
        detail = {"http_status": status, "orig_http_status": orig}
        if status in (404, 410):
            return False, {**detail, "reason": "gone"}, []
        if status in (401, 403):
            if orig == 200:
                return False, {**detail, "reason": "access_blocked"}, []
            return True, {**detail, "reason": "unchanged_status"}, [
                self._again(spec, {"status": status}, f"{url} antwortet weiterhin mit HTTP {status}.")]
        if status != 200:
            if status == orig:
                return True, {**detail, "reason": "unchanged_status"}, [
                    self._again(spec, {"status": status}, f"{url} antwortet weiterhin mit HTTP {status}.")]
            return None, {**detail, "reason": "ambiguous_status"}, []
        body = (resp.text or "")[:4000]
        sig = spec.get("signature")
        if sig == "directory-listing":
            if any(s in body.lower() for s in _LISTING_SIGS):
                return True, {**detail, "reason": "listing_present"}, [
                    self._again(spec, {"path": spec.get("path"), "status": 200,
                                       "signature": "directory-listing"},
                                f"Verzeichnisauflistung unter {url} weiterhin offen.")]
            return False, {**detail, "reason": "listing_gone"}, []
        if sig == "artifact":
            rx = next((r for p, r, _ in _ARTIFACTS if p == spec.get("path")), None)
            if rx is None:
                return None, {**detail, "reason": "artifact_signature_unknown"}, []
            if rx.search(body):
                return True, {**detail, "reason": "artifact_content_present"}, [
                    self._again(spec, {"status": 200}, f"Artefakt {url} weiterhin ausgeliefert.")]
            return False, {**detail, "reason": "artifact_content_gone"}, []
        # 200 ohne Inhalts-Signatur: gegen Catch-all-Antworten absichern.
        base = url[: len(url) - len(spec.get("path") or "")] or url
        baseline = await build_catchall_baseline(net, base, n_samples=3, threshold=0.85)
        if baseline.is_catch_all:
            significant, sim, _reasons = baseline.significant(resp)
            if not significant:
                return None, {**detail, "reason": "catch_all_ambiguous", "similarity": round(sim, 2)}, []
        return True, {**detail, "reason": "still_reachable"}, [
            self._again(spec, {"path": spec.get("path"), "status": 200},
                        f"{url} ist weiterhin erreichbar (HTTP 200).")]

    async def _nikto(self, spec):
        ka = self._kali()
        found = await ka.nikto(spec["url"], agent=self.name)
        nid = spec.get("nikto_id") or ""
        hits = [f for f in found
                if (spec.get("dedup_key") and f.dedup_key == spec["dedup_key"])
                or (nid and str(f.evidence.get("id", "")) == nid)]
        if hits:
            return True, {"reason": "nikto_finding_present", "nikto_id": nid}, [
                self._again(spec, {"tool": "nikto", "id": nid}, "nikto meldet denselben Befund weiterhin.")]
        clean, why = self._tool_clean(ka)
        if not clean:
            return None, why, []
        return False, {"reason": "nikto_finding_absent", "nikto_id": nid}, []

    async def _version(self, spec):
        ka = self._kali()
        if spec.get("tool") == "wpscan":
            found = await ka.wpscan(spec["asset"], agent=self.name)
            versions = [str(f.evidence.get("version")) for f in found if f.evidence.get("version")]
            old = spec.get("version")
            if old in versions:
                return True, {"reason": "same_version_disclosed", "version": old}, [
                    self._again(spec, {"tool": "wpscan", "version": old},
                                f"WordPress {old} wird weiterhin offengelegt.")]
            clean, why = self._tool_clean(ka)
            if not clean:
                return None, why, []
            if versions:
                return None, {"reason": "version_changed", "versions": versions}, []
            return False, {"reason": "version_not_disclosed"}, []
        found = await ka.whatweb(spec["asset"], agent=self.name)
        old = spec.get("tech") or {}
        now: dict = {}
        for f in found:
            for k, v in (f.evidence.get("tech") or {}).items():
                if v:
                    now[str(k)] = str(v)
        same = {k: v for k, v in old.items() if now.get(k) == v}
        if same:
            return True, {"reason": "same_versions_disclosed", "tech": same}, [
                self._again(spec, {"tool": "whatweb", "tech": same},
                            "Dieselben Komponenten-Versionen werden weiterhin offengelegt.")]
        clean, why = self._tool_clean(ka)
        if not clean:
            return None, why, []
        changed = {k: now[k] for k in old if k in now}
        if changed:
            return None, {"reason": "version_changed", "tech": changed}, []
        return False, {"reason": "versions_not_disclosed"}, []

    async def _secret(self, spec):
        if spec.get("tool") != "trufflehog":
            return None, {"reason": "no_recheck_adapter", "tool": spec.get("tool")}, []
        ka = self._kali()
        found = await ka.trufflehog(spec["location"], mode=spec.get("mode") or "filesystem",
                                    agent=self.name)
        hits = [f for f in found if f.dedup_key == spec.get("dedup_key")]
        if hits:
            return True, {"reason": "secret_still_present"}, [
                self._again(spec, {"tool": "trufflehog", "masked": spec.get("masked")},
                            "Dasselbe Secret wird am selben Ort weiterhin gefunden.")]
        clean, why = self._tool_clean(ka)
        if not clean:
            return None, why, []
        # Nicht mehr im Quelltext gefunden – belegt KEINE Rotation/Widerruf.
        return None, {"reason": "not_found_rotation_unverified"}, []

    async def _nuclei(self, spec):
        ka = self._kali()
        tid = spec.get("template_id") or ""
        found = await ka.nuclei(spec["matched_at"], agent=self.name, template_ids=[tid])
        hits = [f for f in found if f.evidence.get("template_id") == tid
                and (f.dedup_key == spec.get("dedup_key")
                     or str(f.evidence.get("matched_at")) == spec["matched_at"])]
        if hits:
            return True, {"reason": "template_matches", "template_id": tid}, [
                self._again(spec, {"tool": "nuclei", "template_id": tid},
                            f"nuclei-Template '{tid}' matcht weiterhin.")]
        clean, why = self._tool_clean(ka)
        if not clean:
            return None, why, []
        return False, {"reason": "template_no_match", "template_id": tid}, []


def recheck_result(findings, dedup_key: str) -> Optional[dict]:
    """Evidence des Meta-Funds für ``dedup_key`` aus einer Lauf-Fundliste."""
    for f in findings or []:
        if getattr(f, "category", "") != RECHECK_CATEGORY:
            continue
        ev = getattr(f, "evidence", None) or {}
        if ev.get("recheck_of") == dedup_key:
            return ev
    return None
