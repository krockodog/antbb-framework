"use client";

import { useEffect, useState } from "react";

import { UserMenu, useMe } from "@/components/user-menu";
import { useI18n } from "@/i18n/language";

// Gleiche obere Leiste wie auf den Unterseiten (antbb/web/templates/_topnav.html,
// Vorbild Red-Koenigin). Styles: /static/topnav.css. /brain hat eine eigene Leiste.
export function SiteHeader() {
  const { t, lang, choose } = useI18n();
  const me = useMe();
  const [hosted, setHosted] = useState<boolean | null>(null);
  const [path, setPath] = useState("/");
  useEffect(() => {
    setPath(window.location.pathname || "/");
    let alive = true;
    fetch("/api/meta", { credentials: "same-origin" })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (alive && data) setHosted(Boolean(data.hosted || data.nav_lab === "osint"));
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);
  const role = (me?.role || "").toLowerCase();
  const canWlan = role === "admin" || role === "member_plus";
  const links: { href: string; label: string }[] = [
    { href: "/red", label: t("nav.red") },
    { href: "/blue", label: t("nav.blue") },
    { href: "/yellow", label: t("nav.yellow") },
  ];
  if (hosted) {
    links.push({ href: "/osint", label: t("nav.osint") });
    if (canWlan) links.push({ href: "/wlan", label: t("nav.wlan") });
  } else {
    links.push({ href: "/wlan", label: t("nav.wlan") });
  }
  links.push(
    { href: "/brain", label: t("nav.brain") },
    { href: "/assets", label: t("nav.assets") },
    { href: "/history", label: t("nav.history") },
  );
  const current = (href: string) =>
    href !== "/brain" && (path === href || path.startsWith(`${href}/`)) ? "page" : undefined;
  const sep = <span className="sep">·</span>;
  // Unterseiten sind FastAPI-Templates: echte <a>-Links statt Next-Client-Navigation.
  return (
    <header className="antbb-topnav">
      <h1>
        <a href="/" className="antbb-topnav-brand">
          antbb · All and One
        </a>
      </h1>
      <nav aria-label="Hauptnavigation">
        <a className="hub-back" href="/" title={t("nav.back_hub")}>
          ← {t("nav.hub")}
        </a>
        {sep} <a href="/">{t("nav.scope")}</a>
        {links.map((link) => (
          <span key={link.href} style={{ display: "contents" }}>
            {sep}{" "}
            <a href={link.href} aria-current={current(link.href)}>
              {link.label}
            </a>
          </span>
        ))}
        <UserMenu me={me} sep={sep} path={path} />
        {sep}{" "}
        <span className="lang-switch" aria-label={t("lang.switch")}>
          <a
            href="?lang=de"
            aria-current={lang === "de" ? "true" : undefined}
            onClick={(e) => {
              e.preventDefault();
              choose("de");
            }}
          >
            DE
          </a>
          {" | "}
          <a
            href="?lang=en"
            aria-current={lang === "en" ? "true" : undefined}
            onClick={(e) => {
              e.preventDefault();
              choose("en");
            }}
          >
            EN
          </a>
        </span>
      </nav>
    </header>
  );
}
