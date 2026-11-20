"use client";

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";

import { buttonVariants } from "@/components/ui/button";
import { useI18n } from "@/i18n/language";
import { cn } from "cn";

// Alle Zustände kommen aus /api/governance/status und /api/governance/audit
// (echte Daten aus Scope-Policy, Oversight, Audit-Trail, Kill Switch).
// Keine Demo-/Mock-Werte: fehlt etwas, wird es ehrlich grau/leer angezeigt.

type RiskRow = {
  level: string;
  examples: string;
  examples_en: string;
  behaviour: string;
  behaviour_en: string;
};

export type GovStatus = {
  policy: { state: string; label: string };
  scope: {
    state: "verified" | "unverified" | "none" | "halted";
    name: string | null;
    scope_ref?: string;
    authorization?: "verified" | "oversight_only" | "unverified";
    allowed_techniques?: string[];
    blocked?: string[];
    max_allowed_risk?: string;
    approval_required_for?: string[];
    test_window?: { start: string; end: string };
  };
  scopes_total: number;
  approval: { state: "enabled" | "pending"; pending: number };
  audit: { state: "active" | "inactive"; entries_24h: number };
  kill_switch: { state: "ready" | "active"; since: number | null; by: string | null };
  runs: { active: number };
  risk_table: RiskRow[];
  viewer: { role: string | null; can_kill: boolean; full_detail: boolean };
};

type AuditEntry = {
  id: number;
  time: string;
  agent: string;
  action: string;
  target: string;
  scope_ref: string;
  risk: string;
  result: string;
};

type Ctx = {
  status: GovStatus | null;
  error: boolean;
  audit: AuditEntry[] | null;
  auditMasked: boolean;
  refresh: () => void;
};

const GovContext = createContext<Ctx>({
  status: null,
  error: false,
  audit: null,
  auditMasked: true,
  refresh: () => {},
});

export function GovernanceProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<GovStatus | null>(null);
  const [error, setError] = useState(false);
  const [audit, setAudit] = useState<AuditEntry[] | null>(null);
  const [auditMasked, setAuditMasked] = useState(true);

  const refresh = useCallback(() => {
    const opts: RequestInit = { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } };
    fetch("/api/governance/status", opts)
      .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
      .then((d: GovStatus) => {
        setStatus(d);
        setError(false);
      })
      .catch(() => setError(true));
    fetch("/api/governance/audit?limit=8", opts)
      .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
      .then((d: { entries: AuditEntry[]; masked: boolean }) => {
        setAudit(d.entries || []);
        setAuditMasked(!!d.masked);
      })
      .catch(() => setAudit(null));
  }, []);

  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, 15000);
    return () => window.clearInterval(id);
  }, [refresh]);

  return <GovContext.Provider value={{ status, error, audit, auditMasked, refresh }}>{children}</GovContext.Provider>;
}

export function useGovernance() {
  return useContext(GovContext);
}

type Tone = "ok" | "warn" | "block" | "off";

function Pill({ label, value, tone }: { label: string; value: string; tone: Tone }) {
  return (
    <span className="gov-pill" data-tone={tone}>
      <span className="gov-dot" aria-hidden="true" />
      <span className="gov-pill-label">{label}:</span> <b>{value}</b>
    </span>
  );
}

async function postJson(path: string, body: unknown) {
  const r = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  let detail = "";
  try {
    const d = await r.json();
    detail = typeof d.detail === "string" ? d.detail : "";
  } catch {
    /* ohne JSON */
  }
  if (!r.ok) throw new Error(detail || `HTTP ${r.status}`);
}

export function KillSwitchButton({ compact = false }: { compact?: boolean }) {
  const { t } = useI18n();
  const { status, refresh } = useGovernance();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  if (!status || !status.viewer.can_kill) return null;
  const active = status.kill_switch.state === "active";
  async function trigger() {
    if (busy) return;
    if (!window.confirm(active ? t("gov.kill.reset_confirm") : t("gov.kill.confirm"))) return;
    setBusy(true);
    try {
      if (active) {
        await postJson("/api/governance/reset", { confirm: "RESET" });
        setMsg(t("gov.kill.reset_done"));
      } else {
        await postJson("/api/governance/kill", { confirm: "STOP", reason: "Startseite" });
        setMsg(t("gov.kill.done"));
      }
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      refresh();
    }
  }
  return (
    <span className="gov-kill-wrap">
      <button
        type="button"
        className={cn("gov-kill", active && "gov-kill-reset", compact && "gov-kill-compact")}
        onClick={trigger}
        disabled={busy}
      >
        {active ? t("gov.kill.reset") : `■ ${t("gov.kill.button")}`}
      </button>
      {msg ? (
        <span className="gov-kill-msg" role="status">
          {msg}
        </span>
      ) : null}
    </span>
  );
}

export function GovernanceBar() {
  const { t } = useI18n();
  const { status, error } = useGovernance();
  const loading = !status && !error;
  const na = error ? t("gov.state.unavailable") : t("gov.state.loading");
  const s = status;
  const scopeTone: Tone = !s ? "off" : s.scope.state === "verified" ? "ok" : s.scope.state === "halted" ? "block" : s.scope.state === "none" ? "off" : "warn";
  const scopeVal = !s
    ? na
    : s.scope.state === "none"
      ? t("gov.state.none")
      : s.scope.state === "halted"
        ? t("gov.state.halted")
        : s.scope.state === "verified"
          ? t("gov.state.verified")
          : t("gov.state.unverified");
  return (
    <div className="gov-bar" role="status" aria-live="polite" aria-busy={loading}>
      <div className="gov-bar-inner">
        <Pill label={t("gov.bar.policy")} value={s ? t("gov.state.default_deny") : na} tone={s ? "ok" : "off"} />
        <Pill label={t("gov.bar.scope")} value={scopeVal} tone={scopeTone} />
        <Pill
          label={t("gov.bar.approval")}
          value={!s ? na : s.approval.state === "pending" ? t("gov.state.pending", { n: s.approval.pending }) : t("gov.state.enabled")}
          tone={!s ? "off" : s.approval.state === "pending" ? "warn" : "ok"}
        />
        <Pill
          label={t("gov.bar.audit")}
          value={!s ? na : s.audit.state === "active" ? t("gov.state.active") : t("gov.state.inactive")}
          tone={!s ? "off" : s.audit.state === "active" ? "ok" : "off"}
        />
        <Pill
          label={t("gov.bar.kill")}
          value={!s ? na : s.kill_switch.state === "active" ? t("gov.state.kill_active") : t("gov.state.ready")}
          tone={!s ? "off" : s.kill_switch.state === "active" ? "block" : "ok"}
        />
        <span className="gov-bar-spacer" />
        <KillSwitchButton compact />
      </div>
    </div>
  );
}

export function SecurityContract() {
  const { t } = useI18n();
  return (
    <aside className="gov-contract" aria-labelledby="gov-contract-title">
      <p id="gov-contract-title" className="gov-contract-title">
        {t("gov.contract.title")}
      </p>
      <ol className="gov-contract-list">
        {[1, 2, 3, 4, 5, 6, 7].map((n) => (
          <li key={n}>
            <span className="gov-contract-n">{n}</span>
            {t(`gov.contract.${n}`)}
          </li>
        ))}
      </ol>
      <p className="gov-contract-foot">{t("gov.contract.enforced")}</p>
    </aside>
  );
}

function fmtWindow(w?: { start: string; end: string }) {
  if (!w || (!w.start && !w.end)) return "";
  return `${w.start ? w.start.replace("T", " ") : "…"} → ${w.end ? w.end.replace("T", " ") : "…"}`;
}

export function LiveSecurityStatus() {
  const { t } = useI18n();
  const { status, error } = useGovernance();
  const s = status;
  const sc = s?.scope;
  const authLabel =
    sc?.authorization === "verified"
      ? t("gov.status.auth.verified")
      : sc?.authorization === "oversight_only"
        ? t("gov.status.auth.oversight_only")
        : t("gov.status.auth.unverified");
  const authTone: Tone = sc?.authorization === "verified" ? "ok" : sc?.authorization === "oversight_only" ? "warn" : "block";
  return (
    <section className="gov-section" aria-labelledby="gov-live-title">
      <h2 id="gov-live-title" className="gov-h2">
        {t("gov.status.title")}
      </h2>
      <div className="gov-live-grid">
        <div className="gov-card gov-live-scope" data-state={sc?.state || "none"}>
          {!s ? (
            <p className="text-sm opacity-70">{error ? t("gov.state.unavailable") : t("gov.state.loading")}</p>
          ) : sc && sc.state !== "none" ? (
            <dl className="gov-dl">
              <dt>{t("gov.status.active_scope")}</dt>
              <dd>
                <b>{sc.name}</b> <span className="opacity-60">({sc.scope_ref})</span>
                {sc.state === "halted" ? <span className="gov-tag" data-tone="block">HALTED</span> : null}
              </dd>
              <dt>{t("gov.status.authorization")}</dt>
              <dd>
                <span className="gov-tag" data-tone={authTone}>
                  {authLabel}
                </span>
              </dd>
              <dt>{t("gov.status.allowed")}</dt>
              <dd>{(sc.allowed_techniques || []).join(", ") || "—"}</dd>
              <dt>{t("gov.status.blocked")}</dt>
              <dd className="gov-blocked">{(sc.blocked || []).join(", ")}</dd>
              <dt>{t("gov.status.max_risk")}</dt>
              <dd>{sc.max_allowed_risk}</dd>
              <dt>{t("gov.status.window")}</dt>
              <dd>{fmtWindow(sc.test_window) || t("gov.status.window_none")}</dd>
              <dt>{t("gov.status.kill")}</dt>
              <dd>
                {s.kill_switch.state === "active" ? (
                  <span className="gov-tag" data-tone="block">
                    {t("gov.state.kill_active")}
                  </span>
                ) : (
                  <span className="gov-tag" data-tone="ok">
                    {t("gov.status.available")}
                  </span>
                )}
              </dd>
            </dl>
          ) : (
            <p className="text-sm">
              <span className="gov-tag" data-tone="off">
                {t("gov.state.none")}
              </span>{" "}
              {t("gov.status.no_scope")}
            </p>
          )}
          {s && !s.viewer.full_detail ? <p className="mt-3 text-xs opacity-60">{t("gov.status.masked")}</p> : null}
        </div>
        <div className="gov-card">
          <dl className="gov-dl gov-dl-compact">
            <dt>{t("gov.status.runs")}</dt>
            <dd>
              <b>{s ? s.runs.active : "…"}</b>
            </dd>
            <dt>{t("gov.status.pending")}</dt>
            <dd>
              <b>{s ? s.approval.pending : "…"}</b>
            </dd>
            <dt>{t("gov.status.policy")}</dt>
            <dd>{t("gov.status.policy_val")}</dd>
            <dt>{t("gov.bar.audit")}</dt>
            <dd>{s ? `${s.audit.entries_24h} / 24h` : "…"}</dd>
          </dl>
          <div className="gov-kill-note">
            <p className="font-semibold">{t("gov.kill.note_title")}</p>
            <p className="text-sm opacity-80">{t("gov.kill.note")}</p>
            <p className="mt-1 text-xs opacity-60">{t("gov.kill.admin_only")}</p>
            <div className="mt-3">
              <KillSwitchButton />
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export function ApprovalWorkflow() {
  const { t } = useI18n();
  return (
    <section className="gov-section" aria-labelledby="gov-approval-title">
      <h2 id="gov-approval-title" className="gov-h2">
        {t("gov.approval.title")}
      </h2>
      <div className="gov-two">
        <div className="gov-card">
          <p className="text-sm leading-relaxed opacity-90">{t("gov.approval.lede")}</p>
          <ol className="gov-flow-v">
            {[1, 2, 3, 4, 5, 6].map((n) => (
              <li key={n}>{t(`gov.approval.s${n}`)}</li>
            ))}
          </ol>
        </div>
        <div className="gov-card">
          <p className="gov-card-k">{t("gov.approval.rules")}</p>
          <ul className="gov-rules">
            {[1, 2, 3, 4, 5].map((n) => (
              <li key={n}>{t(`gov.approval.r${n}`)}</li>
            ))}
          </ul>
          <p className="mt-3 text-sm font-semibold text-[var(--gold)]">{t("gov.approval.human")}</p>
        </div>
      </div>
    </section>
  );
}

const RISK_FALLBACK: RiskRow[] = [];

export function RiskClasses() {
  const { t, lang } = useI18n();
  const { status } = useGovernance();
  const rows = status?.risk_table || RISK_FALLBACK;
  return (
    <section className="gov-section" aria-labelledby="gov-risk-title">
      <h2 id="gov-risk-title" className="gov-h2">
        {t("gov.risk.title")}
      </h2>
      <div className="gov-card gov-table-wrap">
        <table className="gov-table">
          <thead>
            <tr>
              <th>{t("gov.risk.level")}</th>
              <th>{t("gov.risk.examples")}</th>
              <th>{t("gov.risk.behaviour")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={3} className="opacity-70">
                  {t("gov.state.loading")}
                </td>
              </tr>
            ) : (
              rows.map((r) => (
                <tr key={r.level}>
                  <td>
                    <span className="gov-risk" data-risk={r.level}>
                      {r.level}
                    </span>
                  </td>
                  <td>{lang === "en" ? r.examples_en : r.examples}</td>
                  <td>{lang === "en" ? r.behaviour_en : r.behaviour}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function WorkflowSteps() {
  const { t } = useI18n();
  return (
    <section className="gov-section" aria-labelledby="gov-flow-title">
      <h2 id="gov-flow-title" className="gov-h2">
        {t("gov.flow.title")}
      </h2>
      <ol className="gov-flow">
        {[1, 2, 3, 4, 5].map((n) => (
          <li key={n} className="gov-card">
            <span className="gov-flow-n">{n}</span>
            <b>{t(`gov.flow.${n}`)}</b>
            <span className="text-sm opacity-75">{t(`gov.flow.${n}d`)}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}

function resultTone(r: string): Tone {
  if (["started", "approved", "saved", "reset", "allowed"].includes(r)) return "ok";
  if (["denied", "blocked", "halted", "error"].includes(r)) return "block";
  if (["refused", "pending"].includes(r)) return "warn";
  return "off";
}

export function AuditPreview() {
  const { t, lang } = useI18n();
  const { audit, auditMasked } = useGovernance();
  return (
    <section className="gov-section" aria-labelledby="gov-audit-title">
      <h2 id="gov-audit-title" className="gov-h2">
        {t("gov.audit.title")}
      </h2>
      <p className="mb-3 text-sm opacity-80">{t("gov.audit.lede")}</p>
      <div className="gov-card gov-table-wrap">
        <table className="gov-table">
          <thead>
            <tr>
              <th>{t("gov.audit.time")}</th>
              <th>{t("gov.audit.agent")}</th>
              <th>{t("gov.audit.action")}</th>
              <th>{t("gov.audit.target")}</th>
              <th>{t("gov.audit.scope")}</th>
              <th>{t("gov.audit.risk")}</th>
              <th>{t("gov.audit.result")}</th>
            </tr>
          </thead>
          <tbody>
            {audit === null ? (
              <tr>
                <td colSpan={7} className="opacity-70">
                  {t("gov.state.unavailable")}
                </td>
              </tr>
            ) : audit.length === 0 ? (
              <tr>
                <td colSpan={7} className="opacity-70">
                  {t("gov.audit.empty")}
                </td>
              </tr>
            ) : (
              audit.map((e) => (
                <tr key={e.id}>
                  <td className="whitespace-nowrap">
                    {new Date(e.time).toLocaleString(lang === "en" ? "en-GB" : "de-DE", {
                      day: "2-digit",
                      month: "2-digit",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </td>
                  <td>{e.agent}</td>
                  <td>{e.action}</td>
                  <td>{e.target || "—"}</td>
                  <td>{e.scope_ref || "—"}</td>
                  <td>{e.risk ? <span className="gov-risk" data-risk={e.risk}>{e.risk}</span> : "—"}</td>
                  <td>
                    <span className="gov-tag" data-tone={resultTone(e.result)}>
                      {e.result}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      {auditMasked && audit && audit.length ? <p className="mt-2 text-xs opacity-60">{t("gov.audit.masked")}</p> : null}
    </section>
  );
}

export function FinalCta() {
  const { t } = useI18n();
  return (
    <section className="gov-section gov-final">
      <h2 className="gov-h2">{t("gov.final.title")}</h2>
      <p className="mb-4 text-sm opacity-80">{t("gov.final.lede")}</p>
      <a href="/red#new-scope" className={cn(buttonVariants({ size: "lg" }), "h-11 px-5")}>
        {t("gov.cta.new_scope")}
      </a>
    </section>
  );
}
