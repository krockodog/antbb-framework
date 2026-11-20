"use client";

import { useEffect, useState } from "react";

import { useI18n } from "@/i18n/language";
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
    summary: "Authorized Offensive Security im freigegebenen Scope.",
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
  const { t } = useI18n();
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
    <section className="gov-section" aria-labelledby="gov-queens-title">
      <h2 id="gov-queens-title" className="gov-h2">
        {t("gov.queens.title")}
      </h2>
      {error ? (
        <p className="mb-4 text-sm text-[var(--gold)]" role="status">
          {t("queen.api_down")} {error}
        </p>
      ) : null}
      <div className="queen-grid">
        {ORDER.map((queen) => {
          const data = byId.get(queen) ?? STATIC[queen];
          const loading = rows === null && !error;
          return (
            <article key={queen} className="queen-card" data-queen={queen}>
              <p className="text-[0.68rem] tracking-[0.22em] uppercase opacity-80">
                {t("brain.queen")} · {queen}
              </p>
              <h2 className="font-heading queen-card-title mt-3 leading-tight">{t(`gov.${queen}.title`)}</h2>
              <p className="mt-3 text-sm leading-relaxed text-foreground/90">{t(`gov.${queen}.def`)}</p>
              {queen === "red" ? (
                <>
                  <ul className="gov-badges mt-3" aria-label="Security guarantees">
                    <li className="gov-badge">{t("gov.badge.auth")}</li>
                    <li className="gov-badge">{t("gov.badge.scope")}</li>
                    <li className="gov-badge">{t("gov.badge.nodestruct")}</li>
                    <li className="gov-badge">{t("gov.badge.approval")}</li>
                  </ul>
                  <p className="gov-red-risk mt-3 text-xs leading-relaxed">{t("gov.red.risk")}</p>
                </>
              ) : null}
              <p className="gov-boundary mt-3 text-xs leading-relaxed">{t(`gov.${queen}.boundary`)}</p>
              <p className="mt-4 text-sm leading-relaxed">
                <span className="mr-2 text-[0.68rem] tracking-[0.16em] uppercase opacity-60">
                  {t("hub.live_status")}
                </span>
                {loading ? t("queen.live_pending") : data.live_satz}
              </p>
              <div className="mt-3 flex flex-wrap gap-1.5" data-soldiers="1">
                {data.soldier_ids.slice(0, 10).map((id) => (
                  <Badge key={id} variant="outline" className="border-white/15 bg-black/20 text-foreground">
                    {id}
                  </Badge>
                ))}
              </div>
              <a
                href={data.href}
                className={cn(buttonVariants({ size: "lg" }), "queen-cta mt-6 h-10 px-4")}
              >
                {t(`queen.${queen}.cta`)}
              </a>
            </article>
          );
        })}
      </div>
    </section>
  );
}
