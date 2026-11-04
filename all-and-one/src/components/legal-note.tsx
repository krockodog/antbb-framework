"use client";

import { useI18n } from "@/i18n/language";

export function LegalNote() {
  const { t } = useI18n();
  return (
    <p className="legal-note">
      {t("legal.full")} {t("legal.not_substitute")} {t("scope.default_deny")}
    </p>
  );
}
