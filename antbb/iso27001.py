"""ISO/IEC 27001:2022 Annex A catalogue and finding-to-control mapping.

Control IDs and short titles follow ISO/IEC 27001:2022 Annex A (93 controls
in four themes). Full normative text is not reproduced. Nothing here invents
assessment results — mapping is a documented methodology only.
"""
from __future__ import annotations

from typing import Iterable, Optional

# (id, short title de, theme)
_ANNEX_A: list[tuple[str, str, str]] = [
    # A.5 Organisatorische Maßnahmen (37)
    ("A.5.1", "Richtlinien für die Informationssicherheit", "organisatorisch"),
    ("A.5.2", "Rollen und Verantwortlichkeiten in der Informationssicherheit", "organisatorisch"),
    ("A.5.3", "Aufgabentrennung", "organisatorisch"),
    ("A.5.4", "Führungsaufgaben im Management", "organisatorisch"),
    ("A.5.5", "Kontakt mit Behörden", "organisatorisch"),
    ("A.5.6", "Kontakt mit speziellen Interessengruppen", "organisatorisch"),
    ("A.5.7", "Threat Intelligence", "organisatorisch"),
    ("A.5.8", "Informationssicherheit im Projektmanagement", "organisatorisch"),
    ("A.5.9", "Inventarisierung von Informationen und anderen zugeordneten Vermögenswerten", "organisatorisch"),
    ("A.5.10", "Zulässige Nutzung von Informationen und anderen zugeordneten Vermögenswerten", "organisatorisch"),
    ("A.5.11", "Rückgabe von Vermögenswerten", "organisatorisch"),
    ("A.5.12", "Klassifizierung von Informationen", "organisatorisch"),
    ("A.5.13", "Kennzeichnung von Informationen", "organisatorisch"),
    ("A.5.14", "Informationsübermittlung", "organisatorisch"),
    ("A.5.15", "Zugriffskontrolle", "organisatorisch"),
    ("A.5.16", "Identitätsmanagement", "organisatorisch"),
    ("A.5.17", "Authentifizierungsinformationen", "organisatorisch"),
    ("A.5.18", "Zugangsrechte", "organisatorisch"),
    ("A.5.19", "Informationssicherheit in Lieferantenbeziehungen", "organisatorisch"),
    ("A.5.20", "Adressierung von Informationssicherheit in Lieferantenvereinbarungen", "organisatorisch"),
    ("A.5.21", "Management der Informationssicherheit in der IKT-Lieferkette", "organisatorisch"),
    ("A.5.22", "Überwachung, Überprüfung und Änderungsmanagement von Lieferantendienstleistungen", "organisatorisch"),
    ("A.5.23", "Informationssicherheit für die Nutzung von Cloud-Diensten", "organisatorisch"),
    ("A.5.24", "Planung und Vorbereitung des Managements von Informationssicherheitsvorfällen", "organisatorisch"),
    ("A.5.25", "Beurteilung und Entscheidung zu Informationssicherheitsereignissen", "organisatorisch"),
    ("A.5.26", "Reaktion auf Informationssicherheitsvorfälle", "organisatorisch"),
    ("A.5.27", "Lernen aus Informationssicherheitsvorfällen", "organisatorisch"),
    ("A.5.28", "Beweissicherung", "organisatorisch"),
    ("A.5.29", "Informationssicherheit während einer Störung", "organisatorisch"),
    ("A.5.30", "IKT-Bereitschaft für Geschäftskontinuität", "organisatorisch"),
    ("A.5.31", "Rechtliche, behördliche und vertragliche Anforderungen", "organisatorisch"),
    ("A.5.32", "Geistige Eigentumsrechte", "organisatorisch"),
    ("A.5.33", "Schutz von Aufzeichnungen", "organisatorisch"),
    ("A.5.34", "Privatsphäre und Schutz personenbezogener Daten", "organisatorisch"),
    ("A.5.35", "Unabhängige Überprüfung der Informationssicherheit", "organisatorisch"),
    ("A.5.36", "Einhaltung von Richtlinien, Regeln und Standards zur Informationssicherheit", "organisatorisch"),
    ("A.5.37", "Dokumentierte Betriebsabläufe", "organisatorisch"),
    # A.6 Personenbezogene Maßnahmen (8)
    ("A.6.1", "Überprüfung", "personenbezogen"),
    ("A.6.2", "Allgemeine Geschäftsbedingungen", "personenbezogen"),
    ("A.6.3", "Awareness, Schulung und Training zur Informationssicherheit", "personenbezogen"),
    ("A.6.4", "Disziplinarverfahren", "personenbezogen"),
    ("A.6.5", "Verantwortlichkeiten nach Beendigung oder Änderung der Beschäftigung", "personenbezogen"),
    ("A.6.6", "Vertraulichkeits- oder Geheimhaltungsvereinbarungen", "personenbezogen"),
    ("A.6.7", "Telearbeit", "personenbezogen"),
    ("A.6.8", "Melden von Informationssicherheitsereignissen", "personenbezogen"),
    # A.7 Physische Maßnahmen (14)
    ("A.7.1", "Physische Sicherheitsperimeter", "physisch"),
    ("A.7.2", "Physischer Zutritt", "physisch"),
    ("A.7.3", "Sicherung von Büros, Räumen und Einrichtungen", "physisch"),
    ("A.7.4", "Überwachung des physischen Sicherheitsbereichs", "physisch"),
    ("A.7.5", "Schutz vor physischen und umweltbedingten Bedrohungen", "physisch"),
    ("A.7.6", "Arbeiten in Sicherheitsbereichen", "physisch"),
    ("A.7.7", "Schreibtisch und Bildschirm leeren (Clear Desk/Clear Screen)", "physisch"),
    ("A.7.8", "Standort und Schutz von Betriebsmitteln", "physisch"),
    ("A.7.9", "Sicherheit von Vermögenswerten außerhalb des Betriebsgeländes", "physisch"),
    ("A.7.10", "Speichermedien", "physisch"),
    ("A.7.11", "Versorgungseinrichtungen", "physisch"),
    ("A.7.12", "Sicherheit der Verkabelung", "physisch"),
    ("A.7.13", "Instandhaltung der Einrichtungen", "physisch"),
    ("A.7.14", "Sichere Entsorgung oder Wiederverwendung von Betriebsmitteln", "physisch"),
    # A.8 Technologische Maßnahmen (34)
    ("A.8.1", "Endbenutzergeräte", "technologisch"),
    ("A.8.2", "Privilegierte Zugriffsrechte", "technologisch"),
    ("A.8.3", "Beschränkung des Zugriffs auf Informationen", "technologisch"),
    ("A.8.4", "Zugang zu Quellcode", "technologisch"),
    ("A.8.5", "Sichere Authentifizierung", "technologisch"),
    ("A.8.6", "Kapazitätsmanagement", "technologisch"),
    ("A.8.7", "Schutz vor Schadsoftware", "technologisch"),
    ("A.8.8", "Management technischer Schwachstellen", "technologisch"),
    ("A.8.9", "Konfigurationsmanagement", "technologisch"),
    ("A.8.10", "Löschung von Informationen", "technologisch"),
    ("A.8.11", "Datenmaskierung", "technologisch"),
    ("A.8.12", "Verhinderung von Datenlecks (DLP)", "technologisch"),
    ("A.8.13", "Informationssicherung (Backup)", "technologisch"),
    ("A.8.14", "Redundanz von Verarbeitungseinrichtungen", "technologisch"),
    ("A.8.15", "Protokollierung", "technologisch"),
    ("A.8.16", "Überwachungsaktivitäten", "technologisch"),
    ("A.8.17", "Uhrensynchronisation", "technologisch"),
    ("A.8.18", "Nutzung privilegierter Utility-Programme", "technologisch"),
    ("A.8.19", "Installation von Software auf Betriebssystemen", "technologisch"),
    ("A.8.20", "Netzsicherheit", "technologisch"),
    ("A.8.21", "Sicherheit von Netzwerkdiensten", "technologisch"),
    ("A.8.22", "Trennung von Netzen", "technologisch"),
    ("A.8.23", "Web-Filter", "technologisch"),
    ("A.8.24", "Verwendung von Kryptografie", "technologisch"),
    ("A.8.25", "Sichere Entwicklungslebenszyklen", "technologisch"),
    ("A.8.26", "Anforderung an die Anwendungssicherheit", "technologisch"),
    ("A.8.27", "Sichere Systemarchitektur und System-Engineering-Prinzipien", "technologisch"),
    ("A.8.28", "Sicheres Programmieren (Secure Coding)", "technologisch"),
    ("A.8.29", "Sicherheitstests in Entwicklung und Abnahme", "technologisch"),
    ("A.8.30", "Ausgelagerte Entwicklung", "technologisch"),
    ("A.8.31", "Trennung von Entwicklungs-, Test- und Produktionsumgebungen", "technologisch"),
    ("A.8.32", "Änderungsmanagement", "technologisch"),
    ("A.8.33", "Testinformationen", "technologisch"),
    ("A.8.34", "Schutz von Informationssystemen während Audits", "technologisch"),
]


def annex_a_controls() -> list[dict]:
    if len(_ANNEX_A) != 93:
        raise RuntimeError(f"Annex A must contain 93 controls, got {len(_ANNEX_A)}")
    return [{"id": i, "title": t, "theme": th} for i, t, th in _ANNEX_A]


def control_by_id(cid: str) -> Optional[dict]:
    for c in annex_a_controls():
        if c["id"] == cid:
            return c
    return None


# Transparent default Likelihood × Impact from documented severity only.
# This is a methodology default, not a separate expert assessment.
_SEV_LI = {
    "critical": (4, 5),
    "high": (3, 4),
    "medium": (3, 3),
    "low": (2, 2),
    "info": (1, 1),
}

LIKELIHOOD_LABELS = {
    1: "Selten",
    2: "Unwahrscheinlich",
    3: "Möglich",
    4: "Wahrscheinlich",
    5: "Häufig",
}
IMPACT_LABELS = {
    1: "Unwesentlich",
    2: "Gering",
    3: "Moderat",
    4: "Wesentlich",
    5: "Existenzbedrohend",
}

# Default acceptance: score >= 15 (rot) is unacceptable until treated.
# Marked as template default unless the organisation overrides it.
DEFAULT_ACCEPTANCE_THRESHOLD = 15


def severity_to_li(severity: str) -> tuple[int, int, str]:
    sev = (severity or "info").strip().lower()
    L, I = _SEV_LI.get(sev, (1, 1))
    note = (
        "L und I abgeleitet aus der dokumentierten Fund-Severity "
        f"'{sev}' (Methoden-Default, kein separates Experten-Assessment)."
    )
    return L, I, note


def risk_score(likelihood: int, impact: int) -> int:
    return int(likelihood) * int(impact)


def risk_band(score: int, threshold: int = DEFAULT_ACCEPTANCE_THRESHOLD) -> str:
    if score >= max(threshold, 16):
        return "hoch"
    if score >= 10:
        return "mittel"
    if score >= 4:
        return "niedrig"
    return "sehr niedrig"


def risk_color(score: int) -> str:
    if score >= 16:
        return "#8B0000"
    if score >= 10:
        return "#C0392B"
    if score >= 6:
        return "#E67E22"
    if score >= 3:
        return "#F1C40F"
    return "#27AE60"


# Category / agent / keyword → Annex A IDs (methodology, not a finding).
_CATEGORY_CONTROLS: list[tuple[tuple[str, ...], tuple[str, ...]]] = [
    (("tls", "ssl", "cipher", "certificate", "zertifikat", "crypto", "https"),
     ("A.8.24", "A.8.21")),
    (("header", "csp", "hsts", "clickjacking", "x-frame", "security-header"),
     ("A.8.26", "A.8.20")),
    (("auth", "login", "password", "session", "oauth", "mfa", "jwt"),
     ("A.8.5", "A.5.17", "A.5.16")),
    (("xss", "sqli", "injection", "csrf", "ssrf", "path-traversal", "open-redirect",
      "idor", "cors"),
     ("A.8.26", "A.8.28", "A.8.25")),
    (("secret", "token", "api-key", "credential", "leak", "trufflehog", "gitleaks"),
     ("A.8.12", "A.8.11", "A.5.17")),
    (("exposure", "directory", "listing", "information-disclosure", "fingerprint"),
     ("A.8.9", "A.8.20")),
    (("firewall", "port", "network", "waf", "segmentation"),
     ("A.8.20", "A.8.22", "A.8.21")),
    (("patch", "cve", "vulnerability", "schwachstelle", "nuclei", "openvas", "gvm"),
     ("A.8.8", "A.8.16")),
    (("backup", "restore"),
     ("A.8.13",)),
    (("log", "monitor", "siem", "alerting"),
     ("A.8.15", "A.8.16")),
    (("malware", "clamav", "virus"),
     ("A.8.7",)),
    (("hardening", "sysctl", "ssh", "konfig", "config"),
     ("A.8.9", "A.8.20")),
    (("privacy", "dsgvo", "pii", "personenbezogen"),
     ("A.5.34",)),
    (("supply", "dependency", "lieferkette"),
     ("A.5.21", "A.8.30")),
    (("re", "reverse", "binary", "ghidra", "malware-analysis"),
     ("A.8.7", "A.5.28", "A.8.16")),
]


def map_controls(category: str = "", agent: str = "", title: str = "",
                 description: str = "") -> list[str]:
    """Return Annex A IDs suggested by a documented finding's text fields."""
    blob = " ".join([category or "", agent or "", title or "", description or ""]).lower()
    hits: list[str] = []
    for keys, controls in _CATEGORY_CONTROLS:
        if any(k in blob for k in keys):
            for c in controls:
                if c not in hits:
                    hits.append(c)
    if not hits:
        # Generic technical vulnerability management — still a methodology default.
        hits = ["A.8.8"]
    return hits


def default_treatment(band: str) -> str:
    return {
        "hoch": "Vermeiden oder vermindern (Behandlungspflicht laut Default-Akzeptanz)",
        "mittel": "Vermindern oder teilen (Prüfung durch Risikoeigentümer)",
        "niedrig": "Akzeptieren oder vermindern (Dokumentation)",
        "sehr niedrig": "Akzeptieren (Beobachtung)",
    }.get(band, "Auszufüllen")


def residual_default(band: str, treated: bool) -> str:
    if not treated:
        return "keine Daten (Behandlung noch nicht dokumentiert)"
    return "keine Daten (Restrisiko nach Behandlung nicht bewertet)"


assert len(_ANNEX_A) == 93, len(_ANNEX_A)
