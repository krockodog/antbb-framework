"use client";

import { useEffect, useState } from "react";

import de from "@locale/de.json";
import en from "@locale/en.json";

export type Lang = "de" | "en";

const CATALOGS: Record<Lang, Record<string, string>> = { de, en };
const COOKIE = "antbb_lang";
const YEAR = 60 * 60 * 24 * 365;

function normalize(value: string | null | undefined): Lang | null {
  if (!value) return null;
  const tag = value.trim().toLowerCase().replace("_", "-");
  if (tag === "de" || tag.startsWith("de-")) return "de";
  if (tag === "en" || tag.startsWith("en-")) return "en";
  return null;
}

export function resolveLang(explicit?: string | null, cookie?: string | null, accept?: string | null): Lang {
  return normalize(explicit) || normalize(cookie) || normalize(accept) || "de";
}

function readCookie(): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(/(?:^|; )antbb_lang=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

export function useI18n() {
  const [lang, setLang] = useState<Lang>("de");

  useEffect(() => {
    const explicit = new URLSearchParams(window.location.search).get("lang");
    const next = resolveLang(explicit, readCookie(), navigator.language);
    setLang(next);
    document.documentElement.lang = next;
  }, []);

  function t(key: string, vars?: Record<string, string | number>): string {
    const text = CATALOGS[lang][key] || CATALOGS.de[key] || key;
    if (!vars) return text;
    return text.replace(/\{(\w+)\}/g, (_, name: string) =>
      vars[name] == null ? "" : String(vars[name]),
    );
  }

  function hrefFor(next: Lang): string {
    const url = new URL(window.location.href);
    url.searchParams.set("lang", next);
    return `${url.pathname}?${url.searchParams.toString()}${url.hash}`;
  }

  function choose(next: Lang) {
    document.cookie = `${COOKIE}=${next}; Path=/; Max-Age=${YEAR}; SameSite=Lax`;
    window.location.assign(hrefFor(next));
  }

  return { lang, t, choose, hrefFor };
}

export function LanguageSwitcher() {
  const { lang, t, choose } = useI18n();
  return (
    <span className="lang-switch" aria-label={t("lang.switch")}>
      <button type="button" aria-current={lang === "de"} onClick={() => choose("de")}>
        DE
      </button>
      {" | "}
      <button type="button" aria-current={lang === "en"} onClick={() => choose("en")}>
        EN
      </button>
    </span>
  );
}
