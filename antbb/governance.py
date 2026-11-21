"""Governance-Kern: Risikoklassen, Scope-Policy, Audit-Trail, globaler Kill Switch.

Alles hier ist NUR VERSCHÄRFEND. Die bestehenden harten Gates (Scope
default-deny, Oversight-Pflicht, mode_policy auto, nicht destruktiv, FIND and
PROVE only) bleiben unverändert und laufen zusätzlich vor diesen Prüfungen.

- Risikoklassen SAFE < LOW < MEDIUM < HIGH < CRITICAL.
  SAFE/LOW: automatisch im Scope. MEDIUM: ratenlimitiert + geloggt.
  HIGH: explizite Freigabe (Oversight-Häkchen). CRITICAL: per Policy blockiert.
- Scope-Policy je Target (Tabelle scope_policies, additiv, Migration füllt
  Defaults aus mode_policy und den bestehenden Scope-Einträgen).
- Audit-Trail (Tabelle governance_audit, append-only): Run-Starts,
  Gate-Ablehnungen, Freigaben, Policy-Änderungen, Kill Switch.
- Kill Switch (Setting governance.kill_switch + Flag-Datei für Yellow):
  stoppt laufende Scans, blockiert neue Starts bis zum Reset (Admin, auditiert).
Keine Secrets in Tabellen, Logs oder Ausgaben.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger("antbb.governance")

RISK_LEVELS = ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_RANK = {name: i for i, name in enumerate(RISK_LEVELS)}

RISK_TABLE = [
    {"level": "SAFE", "examples": "Passive Recon, DNS, öffentliche Metadaten",
     "examples_en": "Passive recon, DNS, public metadata",
     "behaviour": "Automatisch im Scope erlaubt",
     "behaviour_en": "Allowed automatically in scope"},
    {"level": "LOW", "examples": "HTTP-Fingerprinting, Header-Analyse, begrenzte Enumeration",
     "examples_en": "HTTP fingerprinting, header analysis, limited enumeration",
     "behaviour": "Automatisch im Scope erlaubt, ratenlimitiert",
     "behaviour_en": "Allowed automatically in scope, rate-limited"},
    {"level": "MEDIUM", "examples": "Aktive Scans, Verzeichnis-Enumeration, begrenzte Fuzzing-Tests",
     "examples_en": "Active scans, directory enumeration, limited fuzzing",
     "behaviour": "Rate limit, Logging, Scope-Check",
     "behaviour_en": "Rate limit, logging, scope check"},
    {"level": "HIGH", "examples": "Exploitation, Auth-Bypass, Injection-Validierung, Credential Testing",
     "examples_en": "Exploitation, auth bypass, injection validation, credential testing",
     "behaviour": "Explizite Freigabe erforderlich",
     "behaviour_en": "Explicit approval required"},
    {"level": "CRITICAL", "examples": "Destruktive Aktionen, Persistence, DoS, Datenexfiltration",
     "examples_en": "Destructive actions, persistence, DoS, data exfiltration",
     "behaviour": "Standardmäßig blockiert",
     "behaviour_en": "Blocked by default"},
]

# Technik-Vokabular je Scope (allowed_techniques) -> Risikostufe.
TECHNIQUES: dict[str, dict] = {
    "passive_recon": {"risk": "SAFE", "label": "Passive Recon"},
    "dns": {"risk": "SAFE", "label": "DNS"},
    "public_metadata": {"risk": "SAFE", "label": "Öffentliche Metadaten"},
    "http_fingerprint": {"risk": "LOW", "label": "HTTP-Fingerprinting"},
    "header_analysis": {"risk": "LOW", "label": "Header-Analyse"},
    "tls": {"risk": "LOW", "label": "TLS"},
    "limited_enum": {"risk": "LOW", "label": "Begrenzte Enumeration"},
    "port_scan": {"risk": "MEDIUM", "label": "Port-Scan"},
    "dir_enum": {"risk": "MEDIUM", "label": "Verzeichnis-Enumeration"},
    "limited_fuzzing": {"risk": "MEDIUM", "label": "Begrenztes Fuzzing"},
    "vuln_validation": {"risk": "HIGH", "label": "Schwachstellen-Validierung"},
    "injection_validation": {"risk": "HIGH", "label": "Injection-Validierung"},
    "auth_bypass": {"risk": "HIGH", "label": "Auth-Bypass-Prüfung"},
    "credential_testing": {"risk": "HIGH", "label": "Credential Testing"},
    "exploitation": {"risk": "HIGH", "label": "Exploitation (PoC)"},
}
# Nie wählbar, immer blockiert (Policy).
CRITICAL_TECHNIQUES = {
    "destructive": "Destruktive Aktionen",
    "persistence": "Persistence",
    "dos": "DoS / Last",
    "data_exfiltration": "Datenexfiltration",
    "brute_force": "Brute Force",
}

DEFAULT_TECHNIQUES_DEFENSIVE = [
    "passive_recon", "dns", "public_metadata", "http_fingerprint", "header_analysis",
    "tls", "limited_enum", "port_scan", "dir_enum",
]
DEFAULT_TECHNIQUES_OFFENSIVE = DEFAULT_TECHNIQUES_DEFENSIVE + [
    "limited_fuzzing", "vuln_validation", "injection_validation", "auth_bypass",
]

# Hub-Playbooks (api/catalog.py) -> Risikostufe. Unbekannte Red-Playbooks
# gelten fail-safe als HIGH, Blue/Yellow als LOW.
PLAYBOOK_RISK: dict[str, str] = {
    # Red
    "recon-uebersicht": "MEDIUM", "auth-lage": "MEDIUM", "fuzz-notiz": "MEDIUM",
    "verify-befund": "HIGH", "wifux-wpa2-audit": "HIGH", "shannon-secrets": "LOW",
    "pentagi": "HIGH", "garak": "HIGH", "murphysec": "LOW", "cdk": "MEDIUM",
    "kubescape": "LOW", "ai-infra-guard": "MEDIUM", "sickhackshark": "HIGH",
    "cyberstrikeai": "HIGH",
    # Blue (defensiv, eigene Systeme)
    "wpa2-abwehr": "LOW", "secret-leak-abwehr": "LOW", "agent-governance-toolkit": "LOW",
    "rebuff": "LOW", "openshell": "LOW", "veinmind-tools": "LOW",
    "kubescape-haertung": "LOW", "skillspector": "LOW", "mcp-scanner": "LOW",
    "defending-code-harness": "LOW", "dockerscan-abwehr": "LOW", "patchmgmt": "LOW",
    "tlsposture": "LOW", "greenbone-import": "SAFE", "haertungsnotiz": "SAFE",
    # Yellow (lokale Proben, kein Netz)
    "ghidra-mcp-analyse": "LOW", "re-toolchain-scan": "SAFE",
    "format-klassifikation": "SAFE", "erklaerpfad": "SAFE", "probenkarte": "SAFE",
    "dossier-gelb": "SAFE",
}
CRITICAL_TOKENS = ("brute", "flood", "loadtest", "dos-attack", "ddos", "persist",
                   "exfil", "destruct", "wipe", "ransom")


def risk_rank(level: str) -> int:
    return _RANK.get((level or "").upper(), _RANK["HIGH"])


def max_risk(levels) -> str:
    best = "SAFE"
    for lv in levels:
        if risk_rank(lv) > risk_rank(best):
            best = lv
    return best


def playbook_risk(queen_id: str, playbook_id: str, destructive: bool = False) -> str:
    pid = (playbook_id or "").lower()
    if destructive or any(tok in pid for tok in CRITICAL_TOKENS):
        return "CRITICAL"
    if pid in PLAYBOOK_RISK:
        return PLAYBOOK_RISK[pid]
    if pid.startswith("extras-"):
        return "SAFE"  # Extras = reines passives OSINT
    return "HIGH" if queen_id == "red" else "LOW"


def classify_scan(*, depth: str, engaged: bool, fuzz: bool = False) -> tuple[str, list[str]]:
    """Risiko + benötigte Techniken eines Kolonie-Schwarm-Laufs."""
    tech = ["dns", "http_fingerprint", "header_analysis", "tls", "port_scan"]
    if depth == "intense":
        tech.append("dir_enum")
    if engaged:
        tech += ["vuln_validation", "injection_validation"]
        if fuzz:
            tech.append("limited_fuzzing")
    return max_risk(TECHNIQUES[t]["risk"] for t in tech), tech


# ---------------------------------------------------------------------------
# Store-Zugriff
# ---------------------------------------------------------------------------
_LOCK = threading.RLock()
# Merker-Attribut am Store-Objekt: "Governance-Schema angelegt".
# Bewusst NICHT nach id(conn) (ids werden nach close() wiederverwendet -> stale)
# und nicht nur nach Pfad (":memory:" bzw. neu angelegte Datei am selben Pfad).
_READY_ATTR = "_gov_schema_ready"

POLICY_COLUMNS = (
    ("target_domains", "TEXT NOT NULL DEFAULT '[]'"),
    ("allowed_cidrs", "TEXT NOT NULL DEFAULT '[]'"),
    ("allowed_ports", "TEXT NOT NULL DEFAULT ''"),
    ("allowed_techniques", "TEXT NOT NULL DEFAULT '[]'"),
    ("max_requests_per_minute", "INTEGER NOT NULL DEFAULT 60"),
    ("max_concurrent_agents", "INTEGER NOT NULL DEFAULT 4"),
    ("test_window_start", "TEXT NOT NULL DEFAULT ''"),
    ("test_window_end", "TEXT NOT NULL DEFAULT ''"),
    ("authorized_by", "TEXT NOT NULL DEFAULT ''"),
    ("authorization_document", "TEXT NOT NULL DEFAULT ''"),
    ("emergency_contact", "TEXT NOT NULL DEFAULT ''"),
    ("rules_of_engagement", "TEXT NOT NULL DEFAULT ''"),
    ("kill_switch", "INTEGER NOT NULL DEFAULT 0"),
    ("approval_required_for", "TEXT NOT NULL DEFAULT '[\"HIGH\"]'"),
    ("audit_retention_days", "INTEGER NOT NULL DEFAULT 365"),
    ("updated_at", "REAL"),
    ("updated_by", "TEXT NOT NULL DEFAULT ''"),
)


def default_store():
    from .web.app import svc  # lazy: vermeidet Zyklen
    return svc.store


def ensure_schema(store) -> None:
    if getattr(store, _READY_ATTR, False):
        return
    with _LOCK:
        conn = store._conn
        cols = ",\n".join(f"  {name} {ddl}" for name, ddl in POLICY_COLUMNS)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scope_policies (\n  target_id INTEGER PRIMARY KEY,\n"
            + cols + "\n)")
        have = {r[1] for r in conn.execute("PRAGMA table_info(scope_policies)").fetchall()}
        for name, ddl in POLICY_COLUMNS:
            if name not in have:
                conn.execute(f"ALTER TABLE scope_policies ADD COLUMN {name} {ddl}")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS governance_audit (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts REAL NOT NULL,
                 actor TEXT NOT NULL DEFAULT '',
                 role TEXT NOT NULL DEFAULT '',
                 agent TEXT NOT NULL DEFAULT '',
                 action TEXT NOT NULL DEFAULT '',
                 target TEXT NOT NULL DEFAULT '',
                 target_id INTEGER,
                 scope_ref TEXT NOT NULL DEFAULT '',
                 risk TEXT NOT NULL DEFAULT '',
                 result TEXT NOT NULL DEFAULT '',
                 detail TEXT NOT NULL DEFAULT ''
               )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_gov_audit_ts ON governance_audit(ts)")
        conn.commit()
        try:
            setattr(store, _READY_ATTR, True)
        except (AttributeError, TypeError):
            pass  # Store ohne Attribute: Schema-DDL ist idempotent, läuft dann erneut.
        migrate_policies(store)


def _target_rows(store):
    return store._conn.execute(
        "SELECT id, name, mode_policy, archived_at, owner_user FROM targets").fetchall()


def migrate_policies(store) -> int:
    """Legt für jedes bestehende Target eine Policy an (Defaults, nicht brechend)."""
    made = 0
    with _LOCK:
        conn = store._conn
        have = {r[0] for r in conn.execute("SELECT target_id FROM scope_policies").fetchall()}
        for t in _target_rows(store):
            if t["id"] in have:
                continue
            _insert_default(store, t["id"], t["mode_policy"])
            made += 1
        if made:
            conn.commit()
    return made


def _insert_default(store, target_id: int, mode_policy: str) -> None:
    domains, cidrs = [], []
    for s in store.list_scopes(target_id):
        if not s["allowed"]:
            continue
        if s["kind"] == "domain":
            domains.append(s["value"])
        elif s["kind"] == "ip":
            cidrs.append(s["value"])
    tech = DEFAULT_TECHNIQUES_DEFENSIVE if mode_policy == "defensive" else DEFAULT_TECHNIQUES_OFFENSIVE
    store._conn.execute(
        "INSERT OR IGNORE INTO scope_policies (target_id, target_domains, allowed_cidrs, "
        "allowed_techniques, approval_required_for, updated_at, updated_by) "
        "VALUES (?,?,?,?,?,?,?)",
        (target_id, json.dumps(domains), json.dumps(cidrs), json.dumps(tech),
         json.dumps(["HIGH"]), time.time(), "migration"))


def _jl(raw: Any) -> list:
    try:
        val = json.loads(raw or "[]")
        return val if isinstance(val, list) else []
    except Exception:
        return []


def get_policy(store, target_id: int) -> Optional[dict]:
    ensure_schema(store)
    t = store.get_target(int(target_id))
    if t is None:
        return None
    row = store._conn.execute(
        "SELECT * FROM scope_policies WHERE target_id=?", (int(target_id),)).fetchone()
    if row is None:
        with _LOCK:
            _insert_default(store, int(target_id), t["mode_policy"])
            store._conn.commit()
        row = store._conn.execute(
            "SELECT * FROM scope_policies WHERE target_id=?", (int(target_id),)).fetchone()
    d = dict(row)
    for k in ("target_domains", "allowed_cidrs", "allowed_techniques", "approval_required_for"):
        d[k] = _jl(d.get(k))
    if "HIGH" not in d["approval_required_for"]:
        d["approval_required_for"].append("HIGH")
    d["kill_switch"] = bool(d.get("kill_switch"))
    d["target_name"] = t["name"]
    d["mode_policy"] = t["mode_policy"]
    allowed = [x for x in d["allowed_techniques"] if x in TECHNIQUES]
    d["allowed_techniques"] = allowed
    d["max_allowed_risk"] = max_risk(TECHNIQUES[x]["risk"] for x in allowed) if allowed else "SAFE"
    return d


_DOMAIN_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_PORTS_RE = re.compile(r"^[0-9,\- ]*$")


def _split(value) -> list[str]:
    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"[\s,;]+", str(value or ""))
    return [str(x).strip() for x in items if str(x).strip()]


def _iso_or_empty(value: str, field: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field}: ungültiges Datum/Zeit (ISO, z.B. 2026-11-20T09:00).") from exc
    return dt.isoformat(timespec="minutes")


def validate_policy(payload: dict) -> dict:
    out: dict[str, Any] = {}
    domains = [d.lower() for d in _split(payload.get("target_domains"))]
    for d in domains:
        if not _DOMAIN_RE.match(d):
            raise ValueError(f"target_domains: '{d[:60]}' ist keine gültige Domain.")
    out["target_domains"] = domains[:64]
    cidrs = _split(payload.get("allowed_cidrs") or payload.get("allowed_ips"))
    for c in cidrs:
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError as exc:
            raise ValueError(f"allowed_cidrs: '{c[:60]}' ist keine IP/CIDR.") from exc
    out["allowed_cidrs"] = cidrs[:64]
    ports = str(payload.get("allowed_ports") or "").strip()
    if not _PORTS_RE.match(ports) or len(ports) > 200:
        raise ValueError("allowed_ports: nur Zahlen, Kommas und Bereiche (z.B. 80,443,8000-8100).")
    out["allowed_ports"] = ports
    tech = _split(payload.get("allowed_techniques"))
    bad = [t for t in tech if t not in TECHNIQUES]
    if any(t in CRITICAL_TECHNIQUES for t in bad):
        raise ValueError("CRITICAL-Techniken sind per Policy gesperrt und nicht wählbar.")
    if bad:
        raise ValueError(f"allowed_techniques: unbekannt: {', '.join(b[:30] for b in bad)}")
    out["allowed_techniques"] = list(dict.fromkeys(tech))

    def _int(name, lo, hi, default):
        raw = payload.get(name, default)
        try:
            v = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name}: ganze Zahl erwartet.") from exc
        if not lo <= v <= hi:
            raise ValueError(f"{name}: erlaubt {lo}–{hi}.")
        return v

    out["max_requests_per_minute"] = _int("max_requests_per_minute", 1, 600, 60)
    out["max_concurrent_agents"] = _int("max_concurrent_agents", 0, 64, 4)
    out["audit_retention_days"] = _int("audit_retention_days", 30, 3650, 365)
    out["test_window_start"] = _iso_or_empty(payload.get("test_window_start", ""), "test_window_start")
    out["test_window_end"] = _iso_or_empty(payload.get("test_window_end", ""), "test_window_end")
    if out["test_window_start"] and out["test_window_end"] and \
            out["test_window_end"] <= out["test_window_start"]:
        raise ValueError("test_window: Ende muss nach dem Start liegen.")
    for name, cap in (("authorized_by", 120), ("authorization_document", 300),
                      ("emergency_contact", 200), ("rules_of_engagement", 4000)):
        val = str(payload.get(name) or "").strip()
        if len(val) > cap:
            raise ValueError(f"{name}: höchstens {cap} Zeichen.")
        out[name] = val
    appr = [a.upper() for a in _split(payload.get("approval_required_for"))]
    appr = [a for a in appr if a in ("SAFE", "LOW", "MEDIUM", "HIGH")]
    if "HIGH" not in appr:
        appr.append("HIGH")  # HIGH braucht IMMER Freigabe (nicht abwählbar)
    out["approval_required_for"] = list(dict.fromkeys(appr))
    ks = payload.get("kill_switch")
    out["kill_switch"] = 1 if str(ks).strip().lower() in {"1", "true", "on", "yes", "halted"} else 0
    return out


def save_policy(store, target_id: int, payload: dict, *, actor: str = "", role: str = "") -> dict:
    ensure_schema(store)
    if get_policy(store, target_id) is None:
        raise KeyError("target")
    clean = validate_policy(payload)
    with _LOCK:
        sets = ", ".join(f"{k}=?" for k in clean)
        vals = [json.dumps(v) if isinstance(v, list) else v for v in clean.values()]
        store._conn.execute(
            f"UPDATE scope_policies SET {sets}, updated_at=?, updated_by=? WHERE target_id=?",
            (*vals, time.time(), actor or "", int(target_id)))
        store._conn.commit()
    pol = get_policy(store, target_id)
    audit(store, actor=actor, role=role, agent="scope-manager", action="Scope-Policy gespeichert",
          target=pol["target_name"], target_id=target_id, risk="",
          result="halted" if pol["kill_switch"] else "saved",
          detail=f"techniques={len(pol['allowed_techniques'])} max={pol['max_allowed_risk']}")
    return pol


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
def audit(store=None, *, actor: str = "", role: str = "", agent: str = "", action: str = "",
          target: str = "", target_id: Optional[int] = None, scope_ref: str = "",
          risk: str = "", result: str = "", detail: str = "") -> Optional[int]:
    try:
        store = store or default_store()
        ensure_schema(store)
        if target_id is not None and not scope_ref:
            scope_ref = f"scope-{int(target_id)}"
        with _LOCK:
            cur = store._conn.execute(
                "INSERT INTO governance_audit (ts, actor, role, agent, action, target, target_id, "
                "scope_ref, risk, result, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), (actor or "")[:80], (role or "")[:24], (agent or "")[:60],
                 (action or "")[:120], (target or "")[:160], target_id, (scope_ref or "")[:40],
                 (risk or "")[:10], (result or "")[:24], (detail or "")[:300]))
            store._conn.commit()
            return cur.lastrowid
    except Exception as exc:  # noqa: BLE001 – Audit darf nie den Request stürzen
        log.warning("audit write failed: %s", type(exc).__name__)
        return None


def mask_target(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    host = v.split("://")[-1].split("/")[0]
    parts = host.split(".")
    if len(parts) >= 2:
        return (parts[0][:2] + "***." + parts[-1])
    return v[:2] + "***"


def list_audit(store=None, *, limit: int = 12, full: bool = False) -> list[dict]:
    store = store or default_store()
    ensure_schema(store)
    rows = store._conn.execute(
        "SELECT * FROM governance_audit ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 200)),)
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["time"] = datetime.fromtimestamp(d["ts"], tz=timezone.utc).isoformat(timespec="seconds")
        if not full:
            d["target"] = mask_target(d["target"])
            d["actor"] = d["role"] or "—"
            d["detail"] = ""
        out.append(d)
    return out


def audit_count_since(store, since: float) -> int:
    ensure_schema(store)
    return int(store._conn.execute(
        "SELECT COUNT(*) FROM governance_audit WHERE ts>=?", (since,)).fetchone()[0])


# ---------------------------------------------------------------------------
# Kill Switch
# ---------------------------------------------------------------------------
KILL_KEY = "governance.kill_switch"


def _flag_path(store) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(store.db_path)), "governance_HALTED")


def kill_state(store=None) -> dict:
    store = store or default_store()
    try:
        raw = store.get_setting(KILL_KEY, "")
        st = json.loads(raw) if raw else {}
    except Exception:
        st = {}
    st.setdefault("active", False)
    return st


def is_halted(store=None) -> bool:
    try:
        return bool(kill_state(store).get("active"))
    except Exception:
        return False


def halted_flag_file_exists(data_dir: Optional[str] = None) -> bool:
    """Billiger Check für Prozessteile ohne Store (Yellow-Orchestrator)."""
    cands = []
    if data_dir:
        cands.append(os.path.join(data_dir, "governance_HALTED"))
    db = os.environ.get("ANTBB_DB")
    if db:
        cands.append(os.path.join(os.path.dirname(os.path.abspath(db)), "governance_HALTED"))
    cands.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "data", "governance_HALTED"))
    return any(os.path.exists(p) for p in cands)


def activate_kill(store=None, *, actor: str, role: str, reason: str = "") -> dict:
    store = store or default_store()
    ensure_schema(store)
    stopped: list[str] = []
    try:
        from .web import app as webapp
        with webapp._SCAN_LOCK:
            if webapp.SCAN_STATE.get("status") == "running":
                webapp.SCAN_STATE["cancel_requested"] = True
                stopped.append(f"swarm-scan target={webapp.SCAN_STATE.get('target_id')}")
        try:
            webapp._push_feed({"ts": time.time(), "msg": f"🛑 KILL SWITCH von {actor}: alle Agenten gestoppt"})
        except Exception:
            pass
    except Exception as exc:  # noqa: BLE001
        log.warning("kill: scan cancel failed: %s", type(exc).__name__)
    state = {"active": True, "by": actor, "role": role, "at": time.time(),
             "reason": (reason or "")[:200], "stopped": stopped}
    store.set_setting(KILL_KEY, json.dumps(state))
    try:
        with open(_flag_path(store), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"by": actor, "at": state["at"]}))
    except OSError as exc:
        log.warning("kill flag file failed: %s", type(exc).__name__)
    audit(store, actor=actor, role=role, agent="kill-switch", action="STOP ALL AGENTS",
          target="*", scope_ref="global", risk="", result="halted",
          detail=(f"gestoppt: {', '.join(stopped) or 'kein laufender Lauf'}; "
                  f"Grund: {reason[:120]}" if reason else
                  f"gestoppt: {', '.join(stopped) or 'kein laufender Lauf'}"))
    notified = _notify(store, "kill_switch", actor, "/api/governance/kill",
                       f"STOP ALL AGENTS durch {actor}. Neue Starts blockiert bis Reset.")
    state["notified"] = notified
    return state


def reset_kill(store=None, *, actor: str, role: str) -> dict:
    store = store or default_store()
    prev = kill_state(store)
    state = {"active": False, "by": actor, "role": role, "at": time.time(),
             "previous": {"by": prev.get("by"), "at": prev.get("at")}}
    store.set_setting(KILL_KEY, json.dumps(state))
    try:
        os.remove(_flag_path(store))
    except OSError:
        pass
    audit(store, actor=actor, role=role, agent="kill-switch", action="Kill Switch zurückgesetzt",
          target="*", scope_ref="global", result="reset", detail="Neue Starts wieder erlaubt (Gates unverändert)")
    _notify(store, "kill_switch_reset", actor, "/api/governance/reset",
            f"Kill Switch zurückgesetzt durch {actor}.")
    return state


def _notify(store, kind: str, actor: str, path: str, detail: str) -> bool:
    try:
        from . import alerts
        aid = alerts.raise_alert(store, kind, username=actor, path=path, detail=detail,
                                 severity="high")
        return bool(aid) and alerts.ntfy_configured()
    except Exception as exc:  # noqa: BLE001
        log.warning("kill notify failed: %s", type(exc).__name__)
        return False


# ---------------------------------------------------------------------------
# Gate (nur verschärfend) für Kolonie-Schwarm-Läufe
# ---------------------------------------------------------------------------
class GovernanceBlocked(PermissionError):
    def __init__(self, status: int, detail: str, risk: str = ""):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.risk = risk


def _now_local_iso() -> datetime:
    return datetime.now().astimezone()


def _parse_window(value: str) -> Optional[datetime]:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.astimezone()  # Server-Lokalzeit
    return dt


def enforce_scan(store, target_id: int, *, risk: str, techniques: list[str],
                 approved: bool) -> dict:
    """Zusätzliche Policy-Prüfung. Wirft GovernanceBlocked. Gibt die Policy zurück."""
    if is_halted(store):
        raise GovernanceBlocked(423, "KILL SWITCH aktiv: alle Agenten gestoppt, keine neuen "
                                     "Läufe bis zum Reset durch den Admin.", risk)
    if risk == "CRITICAL":
        raise GovernanceBlocked(403, "CRITICAL: per Policy blockiert.", risk)
    pol = get_policy(store, target_id)
    if pol is None:
        raise GovernanceBlocked(404, "Unbekanntes Ziel.", risk)
    if pol["kill_switch"]:
        raise GovernanceBlocked(423, "Scope-Status HALTED (Scope-Kill-Switch). Kein Lauf.", risk)
    now = _now_local_iso()
    start, end = _parse_window(pol["test_window_start"]), _parse_window(pol["test_window_end"])
    if start and now < start:
        raise GovernanceBlocked(403, f"Außerhalb des Testfensters (beginnt {pol['test_window_start']}).", risk)
    if end and now > end:
        raise GovernanceBlocked(403, f"Testfenster abgelaufen ({pol['test_window_end']}).", risk)
    if pol["max_concurrent_agents"] <= 0:
        raise GovernanceBlocked(403, "max_concurrent_agents = 0: Scope erlaubt keine Agenten.", risk)
    missing = [t for t in techniques if t not in pol["allowed_techniques"]]
    if missing:
        labels = ", ".join(TECHNIQUES[t]["label"] for t in missing)
        raise GovernanceBlocked(403, f"Technik im Scope nicht erlaubt: {labels} (Risiko {risk}).", risk)
    if risk in pol["approval_required_for"] and not approved:
        raise GovernanceBlocked(403, f"Risiko {risk} braucht eine explizite Freigabe "
                                     "(Human-Oversight-Häkchen für diesen Lauf).", risk)
    return pol


# ---------------------------------------------------------------------------
# Status für Startseite/Statusleiste
# ---------------------------------------------------------------------------
def _authorization_state(store, target_id: int, pol: dict) -> str:
    confirmed = store.is_confirmed(target_id)
    if confirmed and pol["authorized_by"] and pol["authorization_document"]:
        return "verified"
    if confirmed:
        return "oversight_only"
    return "unverified"


def status(store=None, *, user: Optional[dict] = None, visible_targets=None,
           running: Optional[dict] = None) -> dict:
    store = store or default_store()
    ensure_schema(store)
    user = user or {}
    role = (user.get("role") or "").lower()
    full = role in ("admin", "")
    ks = kill_state(store)
    targets = [t for t in (visible_targets if visible_targets is not None else store.list_targets())]
    targets = [t for t in targets if not t["archived_at"]] if targets and "archived_at" in targets[0].keys() else targets
    scoped = []
    for t in targets:
        allowed = [s for s in store.list_scopes(t["id"]) if s["allowed"]]
        if allowed:
            scoped.append(t)
    active = None
    run_tid = (running or {}).get("target_id")
    if run_tid:
        active = next((t for t in scoped if int(t["id"]) == int(run_tid)), None)
    if active is None and scoped:
        last = store._conn.execute(
            "SELECT target_id FROM run_history WHERE target_id IS NOT NULL ORDER BY id DESC LIMIT 20"
        ).fetchall()
        ids = [int(r[0]) for r in last]
        active = next((t for i in ids for t in scoped if int(t["id"]) == i), None) or scoped[-1]
    pending = sum(1 for t in scoped if not store.is_confirmed(t["id"]))
    scope_info: dict[str, Any] = {"state": "none", "name": None}
    if active is not None:
        pol = get_policy(store, active["id"])
        auth = _authorization_state(store, active["id"], pol)
        allowed = [TECHNIQUES[t]["label"] for t in pol["allowed_techniques"]]
        blocked = [v["label"] for k, v in TECHNIQUES.items() if k not in pol["allowed_techniques"]]
        blocked += list(CRITICAL_TECHNIQUES.values())
        state = "halted" if (ks.get("active") or pol["kill_switch"]) else (
            "verified" if auth == "verified" else "unverified")
        scope_info = {
            "state": state,
            "name": active["name"] if full else mask_target(active["name"]),
            "scope_ref": f"scope-{active['id']}",
            "authorization": auth,
            "allowed_techniques": allowed,
            "blocked": blocked,
            "max_allowed_risk": pol["max_allowed_risk"],
            "approval_required_for": pol["approval_required_for"],
            "test_window": {"start": pol["test_window_start"], "end": pol["test_window_end"]},
            "has_emergency_contact": bool(pol["emergency_contact"]),
            "has_rules_of_engagement": bool(pol["rules_of_engagement"]),
            "max_concurrent_agents": pol["max_concurrent_agents"],
            "max_requests_per_minute": pol["max_requests_per_minute"],
        }
    since = time.time() - 86400
    try:
        n24 = audit_count_since(store, since)
        audit_ok = True
    except Exception:
        n24, audit_ok = 0, False
    runs_active = 1 if (running or {}).get("status") == "running" else 0
    return {
        "policy": {"state": "active", "label": "DEFAULT-DENY"},
        "scope": scope_info,
        "scopes_total": len(scoped),
        "approval": {"state": "pending" if pending else "enabled", "pending": pending,
                     "rule": "HIGH → explizite Freigabe; CRITICAL → blockiert"},
        "audit": {"state": "active" if audit_ok else "inactive", "entries_24h": n24},
        "kill_switch": {"state": "active" if ks.get("active") else "ready",
                        "since": ks.get("at") if ks.get("active") else None,
                        "by": (ks.get("by") if full else None) if ks.get("active") else None},
        "runs": {"active": runs_active},
        "risk_table": RISK_TABLE,
        "techniques": {k: v for k, v in TECHNIQUES.items()},
        "critical_techniques": CRITICAL_TECHNIQUES,
        "viewer": {"role": role or None, "can_kill": role in ("admin", "member_plus", ""),
                   "full_detail": full},
    }
