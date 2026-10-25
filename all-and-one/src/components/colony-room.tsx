"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";

import { LegalNote } from "@/components/legal-note";
import { SiteHeader } from "@/components/site-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { QueenId } from "@/lib/brand";
import type { ClassifyResult, QueenDetail } from "@/lib/types";

const WORD: Record<QueenId, string> = {
  red: "Rot",
  blue: "Blau",
  yellow: "Gelb",
};

const ROLE: Record<QueenId, string> = {
  red: "Red-Teaming",
  blue: "Blue Safety-Teaming",
  yellow: "Yellow Reverse-Teaming",
};

export function ColonyRoom({ queen }: { queen: QueenId }) {
  const [detail, setDetail] = useState<QueenDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<string | null>(null);
  const [scopeText, setScopeText] = useState("");
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [soldierId, setSoldierId] = useState<string | null>(null);
  const [playbookId, setPlaybookId] = useState<string | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [probeName, setProbeName] = useState("");
  const [classify, setClassify] = useState<ClassifyResult | null>(null);

  const load = useCallback(async () => {
    const next = await api<QueenDetail>(`/api/queens/${queen}`);
    setDetail(next);
    setError(null);
    return next;
  }, [queen]);

  useEffect(() => {
    let alive = true;
    api<QueenDetail>(`/api/queens/${queen}`)
      .then((next) => {
        if (!alive) return;
        setDetail(next);
        setScopeText(next.scope.join("\n"));
        setPicked(next.scope.slice(0, 1));
        const first = next.soldiers[0];
        if (first) {
          setSoldierId(first.soldier_id);
          setPlaybookId(first.playbook_ids[0] ?? null);
        }
      })
      .catch((reason: unknown) => {
        if (!alive) return;
        setError(reason instanceof Error ? reason.message : "Die Kolonie antwortet nicht.");
      });
    return () => {
      alive = false;
    };
  }, [queen]);

  const soldier = detail?.soldiers.find((item) => item.soldier_id === soldierId) ?? null;
  const playbook = detail?.playbooks.find((item) => item.playbook_id === playbookId) ?? null;
  const needsProbe = Boolean(playbook?.needs_probe);

  const blockReason = useMemo(() => {
    if (!detail) return "Die Kolonie wird gelesen.";
    if (!detail.oversight) return "Oversight fehlt. Aktive Arbeit bleibt aus.";
    if (detail.scope.length === 0) return "Scope ist leer. Default-deny lässt keinen Lauf zu.";
    if (!soldier || !playbook) return "Wähle eine Soldatin und ein Playbook.";
    if (!soldier.playbook_ids.includes(playbook.playbook_id)) {
      return "Diese Soldatin führt das Playbook nicht.";
    }
    if (picked.length === 0) return "Wähle mindestens ein Ziel aus der Allowlist.";
    if (needsProbe && !probeName.trim()) return "Für diesen Lauf brauche ich einen Probenamen.";
    return null;
  }, [detail, needsProbe, picked.length, playbook, probeName, soldier]);

  async function saveScope() {
    setBusy(true);
    setBanner(null);
    try {
      const allow = scopeText
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean);
      const saved = await api<{ allow: string[] }>(`/api/queens/${queen}/scope`, {
        method: "PUT",
        body: JSON.stringify({ allow }),
      });
      setDirty(false);
      setPicked(saved.allow.slice(0, 1));
      await load();
      setBanner(saved.allow.length === 0 ? "Allowlist geleert. Default-deny gilt." : "Allowlist gesetzt.");
    } catch (reason) {
      setBanner(reason instanceof Error ? reason.message : "Scope ließ sich nicht setzen.");
    } finally {
      setBusy(false);
    }
  }

  async function setOversight(armed: boolean) {
    setBusy(true);
    setBanner(null);
    try {
      await api(`/api/queens/${queen}/oversight`, {
        method: "POST",
        body: JSON.stringify({ armed }),
      });
      await load();
    } catch (reason) {
      setBanner(reason instanceof Error ? reason.message : "Oversight ließ sich nicht setzen.");
    } finally {
      setBusy(false);
    }
  }

  async function startRun() {
    if (!soldier || !playbook || blockReason) return;
    setBusy(true);
    setBanner(null);
    try {
      const dossier = await api<{ run_id: string }>(`/api/queens/${queen}/runs`, {
        method: "POST",
        body: JSON.stringify({
          soldier_id: soldier.soldier_id,
          playbook_id: playbook.playbook_id,
          oversight: true,
          targets: picked,
          probe_name: needsProbe ? probeName.trim() : null,
        }),
      });
      if (!dirty) {
        const next = await load();
        setScopeText(next.scope.join("\n"));
      } else {
        await load();
      }
      setBanner(`Dossier ${dossier.run_id.slice(0, 8)} liegt in der Kolonie.`);
    } catch (reason) {
      setBanner(reason instanceof Error ? reason.message : "Der Lauf bleibt aus.");
    } finally {
      setBusy(false);
    }
  }

  async function classifyProbe() {
    setBusy(true);
    setBanner(null);
    try {
      const result = await api<ClassifyResult>("/api/queens/yellow/classify", {
        method: "POST",
        body: JSON.stringify({
          name: probeName.trim() || "probe.exe",
          oversight: Boolean(detail?.oversight),
        }),
      });
      setClassify(result);
    } catch (reason) {
      setBanner(reason instanceof Error ? reason.message : "Die Klassifikation bleibt aus.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="relative min-h-dvh" data-queen={queen}>
      <div className="atmosphere" aria-hidden="true">
        <span className={`orb orb-${queen}`} />
      </div>
      <div className="grain" aria-hidden="true" />
      <div className="relative z-10 mx-auto max-w-6xl px-5 py-6 md:px-8">
        <SiteHeader />
        <header className="mt-10 max-w-3xl">
          <p className="text-[0.72rem] tracking-[0.22em] uppercase opacity-70">
            Königin · {WORD[queen]} · {detail?.kicker ?? ROLE[queen]}
          </p>
          <h1 className="font-heading mt-3 text-5xl md:text-6xl">
            {detail?.name ?? (queen === "red" ? "Rote Königin" : queen === "blue" ? "Blaue Königin" : "Gelbe Königin")}
          </h1>
          <p className="mt-4 text-lg leading-relaxed text-foreground/80">
            {detail?.summary ?? "Die Kolonie wird gelesen."}
          </p>
          {queen === "red" ? (
            <p className="mt-3 text-sm text-foreground/65">
              Kanonische Route: /red. Ältere Arbeitstitel bleiben Namen im Text und bekommen keine zweite Oberfläche.
            </p>
          ) : null}
        </header>

        {error ? (
          <p className="mt-8 rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm" role="alert">
            {error} Ich starte `./run.sh`, wenn die API fehlt.
          </p>
        ) : null}
        {banner ? (
          <p className="mt-6 rounded-xl border border-white/10 bg-black/30 px-4 py-3 text-sm" role="status">
            {banner}
          </p>
        ) : null}

        {!detail && !error ? (
          <p className="mt-10 text-sm text-foreground/70">Soldaten, Playbooks und Scope werden gelesen.</p>
        ) : null}

        {detail ? (
          <div className="mt-10 grid gap-6 lg:grid-cols-[280px_minmax(0,1fr)_300px]">
            <section className="space-y-4">
              <Card className="border-0 bg-black/25 ring-white/10">
                <CardContent className="space-y-3">
                  <p className="text-[0.68rem] tracking-[0.16em] uppercase opacity-60">Live-Status</p>
                  <p className="text-sm leading-relaxed">{detail.live_satz}</p>
                  <p className="text-sm opacity-75">{detail.strip_teil}</p>
                </CardContent>
              </Card>
              <Card className="border-0 bg-black/25 ring-white/10">
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between gap-3">
                    <Label htmlFor="oversight">Oversight</Label>
                    <Switch
                      id="oversight"
                      checked={detail.oversight}
                      disabled={busy}
                      onCheckedChange={(checked) => {
                        void setOversight(checked);
                      }}
                    />
                  </div>
                  <p className="text-sm leading-relaxed text-foreground/70">
                    Ohne dieses Häkchen starte ich keinen Lauf. Der Rechtshinweis ersetzt es nicht.
                  </p>
                  <Separator className="bg-white/10" />
                  <Label htmlFor="scope">Scope</Label>
                  <p className="text-sm leading-relaxed text-foreground/70">
                    Default-deny. Leer heißt: kein Ziel, kein Lauf. Eine Zeile, ein freigegebenes Ziel.
                  </p>
                  <Textarea
                    id="scope"
                    value={scopeText}
                    onChange={(event) => {
                      setScopeText(event.target.value);
                      setDirty(true);
                    }}
                    placeholder="labor.intern"
                    className="min-h-28 bg-black/30"
                  />
                  <Button type="button" disabled={busy} onClick={() => void saveScope()}>
                    Allowlist setzen
                  </Button>
                  {detail.scope.length > 0 ? (
                    <ul className="space-y-2">
                      {detail.scope.map((target) => (
                        <li key={target} className="flex items-center gap-2 text-sm">
                          <input
                            type="checkbox"
                            className="size-4 accent-[var(--gold)]"
                            checked={picked.includes(target)}
                            onChange={(event) => {
                              setPicked((current) =>
                                event.target.checked
                                  ? [...current, target]
                                  : current.filter((item) => item !== target),
                              );
                            }}
                          />
                          <span>{target}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-foreground/60">Noch kein Ziel auf der Allowlist.</p>
                  )}
                </CardContent>
              </Card>
            </section>

            <section>
              <h2 className="text-[0.72rem] tracking-[0.18em] uppercase opacity-60">Soldaten</h2>
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                {detail.soldiers.map((item) => {
                  const active = item.soldier_id === soldierId;
                  return (
                    <button
                      key={item.soldier_id}
                      type="button"
                      onClick={() => {
                        setSoldierId(item.soldier_id);
                        setPlaybookId(item.playbook_ids[0] ?? null);
                      }}
                      className={`rounded-2xl border px-4 py-4 text-left transition ${
                        active ? "border-[var(--gold)] bg-black/40" : "border-white/10 bg-black/25 hover:border-white/25"
                      }`}
                    >
                      <span className="block font-heading text-2xl">{item.name}</span>
                      <span className="mt-1 block text-sm opacity-75">{item.role}</span>
                      <span className="mt-3 block text-sm leading-relaxed">{item.live_satz}</span>
                      <span className="mt-3 flex flex-wrap gap-1.5">
                        <Badge variant="outline">{item.mode}</Badge>
                        <Badge variant="secondary">geplant/Mock</Badge>
                      </span>
                    </button>
                  );
                })}
              </div>
              {soldier ? (
                <Card className="mt-4 border-0 bg-black/25 ring-white/10">
                  <CardContent className="space-y-2 text-sm leading-relaxed">
                    <p>
                      {soldier.name} · {soldier.role} · Modus {soldier.mode}
                    </p>
                    <p>{soldier.stub_note}</p>
                    <p className="text-foreground/70">
                      Oversight ist für Läufe nötig. Playbooks: {soldier.playbook_ids.join(", ")}.
                    </p>
                  </CardContent>
                </Card>
              ) : null}
            </section>

            <section>
              <h2 className="text-[0.72rem] tracking-[0.18em] uppercase opacity-60">Playbooks</h2>
              <div className="mt-3 space-y-3">
                {detail.playbooks.map((item) => {
                  const owned = soldier?.playbook_ids.includes(item.playbook_id) ?? false;
                  const active = item.playbook_id === playbookId;
                  return (
                    <button
                      key={item.playbook_id}
                      type="button"
                      disabled={!owned}
                      onClick={() => setPlaybookId(item.playbook_id)}
                      className={`block w-full rounded-2xl border px-4 py-3 text-left ${
                        active ? "border-[var(--gold)] bg-black/40" : "border-white/10 bg-black/25"
                      } disabled:cursor-not-allowed disabled:opacity-45`}
                    >
                      <span className="block text-sm font-medium">{item.title}</span>
                      <span className="mt-1 block text-sm leading-relaxed text-foreground/75">{item.summary}</span>
                      <span className="mt-2 block text-xs tracking-wide text-[var(--gold)]">{item.stub_note}</span>
                    </button>
                  );
                })}
              </div>
              {needsProbe ? (
                <label className="mt-4 block text-sm">
                  Probename
                  <Input
                    value={probeName}
                    onChange={(event) => setProbeName(event.target.value)}
                    placeholder="probe.exe"
                    className="mt-2 h-9 border-white/15 bg-black/30"
                  />
                </label>
              ) : null}
              <Button
                type="button"
                className="mt-4 h-10 w-full"
                disabled={busy || Boolean(blockReason)}
                onClick={() => void startRun()}
              >
                Lauf ins Dossier schreiben
              </Button>
              {blockReason ? <p className="mt-2 text-sm text-foreground/65">{blockReason}</p> : null}
            </section>
          </div>
        ) : null}

        {queen === "yellow" && detail ? (
          <section className="mt-10 rounded-2xl border border-white/10 bg-black/25 p-5">
            <h2 className="font-heading text-3xl">Erklärbärin</h2>
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-foreground/75">
              Ich klassifiziere den Namen. Die Datei bleibt zu. Ohne Oversight zeige ich nur die Hülle.
            </p>
            <div className="mt-4 flex flex-wrap gap-3">
              <Input
                value={probeName}
                onChange={(event) => setProbeName(event.target.value)}
                placeholder="probe.exe, libdemo.so, firmware.hex"
                className="h-10 min-w-[16rem] flex-1 border-white/15 bg-black/30"
              />
              <Button type="button" variant="outline" disabled={busy} onClick={() => void classifyProbe()}>
                Klassifikation ansehen
              </Button>
              <Link href="/yellow/laeufe" className="self-center text-sm text-[var(--gold)] underline-offset-4 hover:underline">
                Läufe öffnen
              </Link>
            </div>
            {classify ? (
              <div className="mt-5 space-y-3">
                <p className="text-sm">
                  {classify.kind_label} · {classify.note}
                </p>
                <ol className="space-y-3">
                  {classify.steps.map((step) => (
                    <li key={step.order} className="rounded-xl border border-white/10 bg-black/30 px-4 py-3">
                      <p className="text-sm font-medium">
                        {step.order}. {step.title}
                      </p>
                      <p className="mt-1 text-xs tracking-wide text-[var(--gold)]">
                        {step.tool} · {step.stub_note}
                      </p>
                      <p className="mt-2 text-sm leading-relaxed">{step.erklaerbaerin}</p>
                    </li>
                  ))}
                </ol>
                {classify.withheld ? (
                  <p className="text-sm text-foreground/70">
                    {classify.withheld_count} tiefere Schritte bleiben ohne Oversight zurück.
                  </p>
                ) : null}
              </div>
            ) : null}
          </section>
        ) : null}

        {detail ? (
          <section className="mt-10 grid gap-6 md:grid-cols-2">
            <div>
              <h2 className="text-[0.72rem] tracking-[0.18em] uppercase opacity-60">Dossier</h2>
              {detail.runs.length === 0 ? (
                <p className="mt-3 text-sm text-foreground/70">
                  Noch kein Lauf. Zuerst Scope setzen und Oversight anhaken.
                </p>
              ) : (
                <ul className="mt-3 space-y-2">
                  {detail.runs.map((run) => (
                    <li key={run.run_id} className="rounded-xl border border-white/10 bg-black/25 px-4 py-3 text-sm">
                      <span className="block text-foreground/60">{run.created_at}</span>
                      <span className="mt-1 block">{run.summary}</span>
                      {queen === "yellow" ? (
                        <Link className="mt-2 inline-block text-[var(--gold)]" href={`/yellow/laeufe#${run.run_id}`}>
                          Im Laufverzeichnis öffnen
                        </Link>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div>
              <h2 className="text-[0.72rem] tracking-[0.18em] uppercase opacity-60">Ledger</h2>
              {detail.ledger.length === 0 ? (
                <p className="mt-3 text-sm text-foreground/70">Das Ledger dieser Königin ist noch leer.</p>
              ) : (
                <ul className="mt-3 space-y-2">
                  {detail.ledger.map((entry) => (
                    <li key={`${entry.run_id}-${entry.at}`} className="text-sm leading-relaxed text-foreground/80">
                      <span className="text-foreground/50">{entry.at}</span> {entry.message}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>
        ) : null}

        <footer className="mt-12 pb-6">
          <LegalNote />
          <p className="mt-4 text-sm text-foreground/65">All and One · Red · Blue · Yellow</p>
        </footer>
      </div>
    </main>
  );
}
