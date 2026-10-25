"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { QueenId } from "@/lib/brand";
import type { QueenSummary } from "@/lib/types";
import { cn } from "cn";

const ORDER: QueenId[] = ["red", "blue", "yellow"];

const STATIC: Record<QueenId, QueenSummary> = {
  red: {
    queen_id: "red",
    name: "Rote Königin",
    kicker: "Red-Teaming",
    summary: "Bug Bounty und Pentest im engen Scope. Aktive Arbeit nur mit Scope und Oversight.",
    cta: "Zur Roten Königin",
    href: "/red",
    tut: "Grenzschau",
    strip_teil: "Rot tut Grenzschau",
    live_satz: "Live-Status wird aus der echten Colony gelesen.",
    oversight: false,
    scope: [],
    soldier_ids: [],
    playbook_ids: [],
  },
  blue: {
    queen_id: "blue",
    name: "Blaue Königin",
    kicker: "Blue Safety-Teaming",
    summary: "Schutz und Hardening mit echten Colony-Prüfungen und Greenbone-Anbindung.",
    cta: "Zur Blauen Königin",
    href: "/blue",
    tut: "Härtelage",
    strip_teil: "Blau tut Härtelage",
    live_satz: "Live-Status wird aus der echten Colony gelesen.",
    oversight: false,
    scope: [],
    soldier_ids: [],
    playbook_ids: [],
  },
  yellow: {
    queen_id: "yellow",
    name: "Gelbe Königin",
    kicker: "Yellow Reverse-Teaming",
    summary: "Reverse Engineering mit echten RE-Soldaten. Ohne Oversight bleiben tiefe Schritte gesperrt.",
    cta: "Zur Gelben Königin",
    href: "/yellow",
    tut: "Wegerklärung",
    strip_teil: "Gelb tut Wegerklärung",
    live_satz: "Live-Status wird aus der echten Colony gelesen.",
    oversight: false,
    scope: [],
    soldier_ids: [],
    playbook_ids: [],
  },
};

export function QueenCards() {
  const [rows, setRows] = useState<QueenSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api<QueenSummary[]>("/api/queens")
      .then((data) => {
        if (alive) setRows(data);
      })
      .catch((reason: unknown) => {
        if (!alive) return;
        setError(reason instanceof Error ? reason.message : "Die API antwortet nicht.");
      });
    return () => {
      alive = false;
    };
  }, []);

  const byId = new Map((rows ?? []).map((row) => [row.queen_id, row]));

  return (
    <div className="mt-12">
      {error ? (
        <p className="mb-4 text-sm text-[var(--gold)]" role="status">
          Live-Status wartet auf die API. {error}
        </p>
      ) : null}
      <div className="grid gap-4 md:grid-cols-3">
        {ORDER.map((queen) => {
          const data = byId.get(queen) ?? STATIC[queen];
          const loading = rows === null && !error;
          return (
            <article key={queen} className="queen-card" data-queen={queen}>
              <p className="text-[0.68rem] tracking-[0.22em] uppercase opacity-80">
                Königin · {queen === "red" ? "Rot" : queen === "blue" ? "Blau" : "Gelb"}
              </p>
              <h2 className="font-heading mt-3 text-4xl leading-none">{data.name}</h2>
              <p className="mt-2 text-sm tracking-wide opacity-80">{data.kicker}</p>
              <p className="mt-4 text-sm leading-relaxed text-foreground/85">{data.summary}</p>
              <p className="mt-5 text-sm leading-relaxed">
                <span className="mr-2 text-[0.68rem] tracking-[0.16em] uppercase opacity-60">
                  Live-Status
                </span>
                {loading ? "wird gelesen." : data.live_satz}
              </p>
              <div className="mt-4 flex flex-wrap gap-1.5">
                {data.soldier_ids.map((id) => (
                  <Badge key={id} variant="outline" className="border-white/15 bg-black/20 text-foreground">
                    {id}
                  </Badge>
                ))}
              </div>
              <Link
                href={data.href}
                className={cn(buttonVariants({ size: "lg" }), "queen-cta mt-6 h-10 px-4")}
              >
                {data.cta}
              </Link>
            </article>
          );
        })}
      </div>
    </div>
  );
}
