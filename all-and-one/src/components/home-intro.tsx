"use client";

import { SecurityContract } from "@/components/governance";
import { buttonVariants } from "@/components/ui/button";
import { useI18n } from "@/i18n/language";
import { cn } from "cn";

// Hero: Name, Wertversprechen, Kernbotschaft, primärer CTA + Security Contract.
export function HomeIntro() {
  const { t } = useI18n();
  return (
    <section className="home-intro gov-hero">
      <div className="gov-hero-copy">
        <p className="text-[0.72rem] tracking-[0.28em] text-[var(--gold)] uppercase">{t("gov.kicker")}</p>
        <h1 className="font-heading home-title mt-4 max-w-5xl leading-[1.02] text-balance">
          All and One - RED-BLUE-Yellow-Ant-Team
        </h1>
        <p className="gov-core mt-5">{t("gov.core")}</p>
        <div className="home-pitch mt-5 max-w-2xl space-y-3 leading-relaxed text-foreground/85">
          <p>{t("home.pitch")}</p>
          <p>{t("gov.copy.2")}</p>
          <p>{t("gov.copy.3")}</p>
        </div>
        <div className="mt-7 flex flex-wrap gap-3">
          <a href="/red#new-scope" className={cn(buttonVariants({ size: "lg" }), "h-11 px-5")}>
            {t("gov.cta.new_scope")}
          </a>
          <a
            href="/brain"
            className={cn(buttonVariants({ variant: "outline", size: "lg" }), "h-11 border-white/15 bg-transparent px-5")}
          >
            {t("gov.cta.engine")}
          </a>
        </div>
      </div>
      <SecurityContract />
    </section>
  );
}
