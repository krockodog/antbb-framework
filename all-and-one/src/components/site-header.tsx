"use client";

import Link from "next/link";

import { LanguageSwitcher, useI18n } from "@/i18n/language";

export function SiteHeader() {
  const { t } = useI18n();
  const links = [
    { href: "/", label: t("nav.scope") },
    { href: "/red", label: t("nav.red") },
    { href: "/blue", label: t("nav.blue") },
    { href: "/yellow", label: t("nav.yellow") },
    { href: "/wlan", label: t("nav.wlan") },
    { href: "/brain", label: t("nav.brain") },
    { href: "/assets", label: t("nav.assets") },
    { href: "/history", label: t("nav.history") },
  ];
  return (
    <header className="flex flex-wrap items-center justify-between gap-4">
      <Link href="/" className="group block">
        <span className="block text-[0.7rem] tracking-[0.22em] text-[var(--gold)] uppercase">
          All and One
        </span>
        <span className="mt-1 block text-sm text-foreground/80">
          RED-BLUE-Yellow-Ant-Team
        </span>
      </Link>
      <nav className="flex flex-wrap items-center gap-1 text-sm">
        {links.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className="rounded-full px-3 py-1.5 text-foreground/75 transition hover:bg-white/5 hover:text-foreground"
          >
            {link.label}
          </Link>
        ))}
        <LanguageSwitcher />
      </nav>
    </header>
  );
}
