"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { LegalNote } from "@/components/legal-note";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { Dossier, RunRow } from "@/lib/types";

export function Laeufe() {
  const [runs, setRuns] = useState<RunRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [dossier, setDossier] = useState<Dossier | null>(null);

  useEffect(() => {
    let alive = true;
    api<{ runs: RunRow[] }>("/api/queens/yellow/runs")
      .then((body) => {
        if (alive) setRuns(body.runs);
      })
      .catch((reason: unknown) => {
        if (!alive) return;
        setError(reason instanceof Error ? reason.message : "Die Läufe sind nicht lesbar.");
      });
    return () => {
      alive = false;
    };
  }, []);

  async function open(runId: string) {
    setOpenId(runId);
    setDossier(null);
    try {
      const next = await api<Dossier>(`/api/queens/yellow/runs/${runId}`);
      setDossier(next);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Das Dossier bleibt zu.");
    }
  }

  return (
    <main className="relative min-h-dvh">
      <div className="atmosphere" aria-hidden="true">
        <span className="orb orb-yellow" />
      </div>
      <div className="grain" aria-hidden="true" />
      <div className="relative z-10 mx-auto max-w-4xl px-5 py-6 md:px-8">
        <SiteHeader />
        <header className="mt-10">
          <p className="text-[0.72rem] tracking-[0.22em] text-[var(--gold)] uppercase">Gelbe Königin</p>
          <h1 className="font-heading mt-3 text-5xl">Läufe</h1>
          <p className="mt-4 max-w-2xl text-foreground/75">
            Jedes Dossier bleibt bei Gelb. Rot und Blau sehen diese Läufe nicht.
          </p>
        </header>
        {error ? (
          <p className="mt-6 text-sm" role="alert">
            {error}
          </p>
        ) : null}
        {runs === null && !error ? <p className="mt-8 text-sm">Läufe werden gelesen.</p> : null}
        {runs && runs.length === 0 ? (
          <div className="mt-8 rounded-2xl border border-white/10 bg-black/25 p-5">
            <p>Noch kein Lauf. Zuerst auf der Gelben Königin Scope und Oversight setzen.</p>
            <Button className="mt-4" render={<Link href="/yellow" />}>
              Zur Gelben Königin
            </Button>
          </div>
        ) : null}
        <ul className="mt-8 space-y-3">
          {runs?.map((run) => (
            <li key={run.run_id} id={run.run_id} className="rounded-2xl border border-white/10 bg-black/25 p-4">
              <p className="text-sm text-foreground/55">{run.created_at}</p>
              <p className="mt-2 text-sm leading-relaxed">{run.summary}</p>
              <button
                type="button"
                className="mt-3 text-sm text-[var(--gold)]"
                onClick={() => void open(run.run_id)}
              >
                Dossier lesen
              </button>
              {openId === run.run_id && dossier ? (
                <div className="mt-4 space-y-3 border-t border-white/10 pt-4 text-sm">
                  <p>
                    Königin {dossier.queen_id} · Soldatin {dossier.soldier_name} · Playbook {dossier.playbook_title}
                  </p>
                  <p>{dossier.stub_note}</p>
                  <p>Ziele: {dossier.targets.join(", ") || "keine"}</p>
                  {dossier.plan ? (
                    <ol className="space-y-2">
                      {dossier.plan.steps.map((step) => (
                        <li key={step.order}>
                          <span className="text-[var(--gold)]">
                            {step.order}. {step.title}
                          </span>
                          <span className="mt-1 block leading-relaxed">{step.erklaerbaerin}</span>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <p>Dieser Lauf trägt keinen Klassifikationsplan.</p>
                  )}
                </div>
              ) : null}
            </li>
          ))}
        </ul>
        <footer className="mt-12 pb-6">
          <LegalNote />
        </footer>
      </div>
    </main>
  );
}
