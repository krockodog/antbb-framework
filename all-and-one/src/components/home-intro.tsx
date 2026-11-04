"use client";

import Link from "next/link";

import { buttonVariants } from "@/components/ui/button";
import { useI18n } from "@/i18n/language";
import { cn } from "cn";

export function HomeIntro() {
  const { t } = useI18n();
  return (
    <section className="pt-12 md:pt-16">
      <p className="text-[0.72rem] tracking-[0.28em] text-[var(--gold)] uppercase">
        {t("home.kicker")}
      </p>
      <h1 className="font-heading mt-4 max-w-5xl text-[2.6rem] leading-[1.02] text-balance md:text-6xl">
        All and One - RED-BLUE-Yellow-Ant-Team
      </h1>
      <p className="mt-6 max-w-2xl text-lg leading-relaxed text-foreground/80">
        {t("home.pitch")}
      </p>
      <p className="mt-4 text-sm tracking-[0.14em] text-[var(--gold)] uppercase">
        {t("home.roles")}
      </p>
      <div className="mt-8 flex flex-wrap gap-3">
        <Link href="/brain" className={cn(buttonVariants({ size: "lg" }), "h-11 px-5")}>
          {t("home.open_brain")}
        </Link>
        <Link
          href="/yellow"
          className={cn(
            buttonVariants({ variant: "outline", size: "lg" }),
            "h-11 border-white/15 bg-transparent px-5",
          )}
        >
          {t("home.yellow_cases")}
        </Link>
      </div>
    </section>
  );
}
