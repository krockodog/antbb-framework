import Link from "next/link";

import { LegalNote } from "@/components/legal-note";
import { QueenCards } from "@/components/queen-cards";
import { SiteHeader } from "@/components/site-header";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "cn";

export default function Home() {
  return (
    <main className="relative min-h-dvh overflow-hidden">
      <div className="atmosphere" aria-hidden="true">
        <span className="orb orb-red" />
        <span className="orb orb-blue" />
        <span className="orb orb-yellow" />
      </div>
      <div className="grain" aria-hidden="true" />
      <div className="relative z-10 mx-auto flex min-h-dvh max-w-6xl flex-col px-5 py-6 md:px-8">
        <SiteHeader />
        <section className="pt-12 md:pt-16">
          <p className="text-[0.72rem] tracking-[0.28em] text-[var(--gold)] uppercase">
            Drei Königinnen · ein Schwarm
          </p>
          <h1 className="font-heading mt-4 max-w-5xl text-[2.6rem] leading-[1.02] text-balance md:text-6xl">
            All and One - RED-BLUE-Yellow-Ant-Team
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-relaxed text-foreground/80">
            Orchestrierte Ameisenfarmen — die vom Bug Bounty und Pentest über Reverse Engineering bis zum Schutz und Hardening helfen.
          </p>
          <p className="mt-4 text-sm tracking-[0.14em] text-[var(--gold)] uppercase">
            Red-Teaming · Yellow Reverse-Teaming · Blue Safety-Teaming
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link
              href="/brain"
              className={cn(buttonVariants({ size: "lg" }), "h-11 px-5")}
            >
              Neural Brain öffnen
            </Link>
            <Link
              href="/yellow"
              className={cn(
                buttonVariants({ variant: "outline", size: "lg" }),
                "h-11 border-white/15 bg-transparent px-5",
              )}
            >
              Gelbe Fälle
            </Link>
          </div>
        </section>
        <QueenCards />
        <footer className="mt-auto pt-12 pb-2">
          <LegalNote />
          <p className="mt-4 text-sm tracking-wide text-foreground/70">
            All and One · Red · Blue · Yellow
          </p>
        </footer>
      </div>
      <script src="/static/hub-real.js?v=202610240215" defer />
    </main>
  );
}
