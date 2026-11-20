"use client";

import { useEffect, useState, type ReactNode } from "react";

import { useI18n } from "@/i18n/language";

export type Me = { username: string; role: string; is_admin: boolean };

// Wer ist angemeldet? Die Landing ist statisch exportiert, daher /api/me
// (nur mit Session, sonst 401). Ohne Login bleibt der Benutzer-Bereich leer.
export function useMe(): Me | null {
  const [me, setMe] = useState<Me | null>(null);
  useEffect(() => {
    let alive = true;
    fetch("/api/me", { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (alive && data && typeof data.username === "string" && data.username) {
          setMe({ username: data.username, role: String(data.role || ""), is_admin: !!data.is_admin });
        }
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);
  return me;
}

// Benutzer-Bereich rechts in der Leiste, gleiche Reihenfolge wie _topnav.html:
// Admin (nur Admins) · 👤 Benutzer (+ Alarm-Punkt) · Abmelden.
export function UserMenu({ me, sep, path }: { me: Me | null; sep: ReactNode; path: string }) {
  const { t } = useI18n();
  const [alerts, setAlerts] = useState(0);
  const [why, setWhy] = useState("");
  const isAdmin = !!me?.is_admin;

  useEffect(() => {
    if (!isAdmin) return;
    let alive = true;
    const poll = () =>
      // Punkt nur bei neuen Benutzern / kritischen Ereignissen (admin_portal.attention_status)
      fetch("/api/admin/attention", {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      })
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => {
          if (!alive || !d) return;
          setAlerts(d.blink ? Number(d.count) || 1 : 0);
          setWhy(
            (Array.isArray(d.reasons) ? d.reasons : [])
              .map((x: { label: string; count: number; users?: string[] }) =>
                `${x.label}: ${x.count}${x.users && x.users.length ? ` (${x.users.join(", ")})` : ""}`,
              )
              .join(" · "),
          );
        })
        .catch(() => {});
    poll();
    const id = window.setInterval(poll, 15000);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
  }, [isAdmin]);

  if (!me) return null;
  return (
    <span className="antbb-topnav-user" data-user-menu>
      {isAdmin ? (
        <>
          {sep}{" "}
          <a href="/admin/users" aria-current={path.startsWith("/admin") ? "page" : undefined}>
            {t("nav.admin")}
          </a>
        </>
      ) : null}
      {sep}{" "}
      <span className="nav-user">
        <a href="/profile" title={t("nav.profile")}>
          👤 {me.username}
        </a>
        {isAdmin ? (
          <span
            id="alert-dot"
            className="alert-dot"
            hidden={alerts <= 0}
            title={why}
            aria-label={why}
          />
        ) : null}
      </span>
      {sep} <a href="/logout">{t("nav.logout")}</a>
    </span>
  );
}
