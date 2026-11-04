"use client";

import Link from "next/link";

import { SiteHeader } from "@/components/site-header";
import { buttonVariants } from "@/components/ui/button";
import { useI18n } from "@/i18n/language";
import { cn } from "cn";

export default function NotFound() {
  const { t } = useI18n();
  return (
    <main className="mx-auto flex min-h-dvh max-w-3xl flex-col px-5 py-6">
      <SiteHeader />
      <section className="py-20">
        <p className="text-[0.72rem] tracking-[0.22em] text-[var(--gold)] uppercase">
          {t("notfound.kicker")}
        </p>
        <h1 className="font-heading mt-3 text-5xl">{t("notfound.title")}</h1>
        <p className="mt-4 max-w-xl text-foreground/75">{t("notfound.body")}</p>
        <div className="mt-8 flex gap-3">
          <Link href="/" className={cn(buttonVariants({ size: "lg" }), "h-10 px-4")}>
            {t("notfound.hub")}
          </Link>
          <Link
            href="/brain"
            className={cn(buttonVariants({ variant: "outline", size: "lg" }), "h-10 px-4")}
          >
            {t("notfound.brain")}
          </Link>
        </div>
      </section>
    </main>
  );
}
