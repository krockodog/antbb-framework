#!/usr/bin/env python3
"""Erzeugt antbb/extras_osint.json ("Extras") aus dem enna-Katalog.

NUR DATEN: liest ausschliesslich ``src/data/tools.json`` als JSON. Die
enna-Next.js-App wird weder gebaut, gestartet noch installiert (Sentry-DSN
mit PII/Replay, Vercel-Analytics, Discord-Webhook, Werbe-Hooks, husky,
curl|bash-Installer — siehe Analyse 2026-11-11).

Filter: strikt passives OSINT/Recon. Offensives, Exploitation, Phishing,
Wireless, Keylogger, Brute-Force, Takeover, Credential-/Breach-Hunting,
Personen-Geolokalisierung und SOC/IDS/DFIR-Plattformen (kein OSINT) fliegen
raus. Installbefehle werden nur als Hinweis uebernommen, wenn sie keine
Pipe/Download-Kette enthalten; nichts wird automatisch installiert.

Aufruf:  python3 tools/import_extras_from_enna.py /workspace/recon/enna/src/data/tools.json
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "antbb" / "extras_osint.json"

INCLUDE_CATEGORIES = {
    "osint-general": "OSINT allgemein",
    "osint-social": "OSINT Social-Media / Username",
    "subdomain-enum": "Domain / Subdomain (passiv)",
    "threat-intel": "Threat-Intel / IOC",
}
# Passive Einzelstuecke aus sonst ausgeschlossenen Kategorien.
EXTRA_SLUGS = {
    "waybackurls": "Archive / URL-Historie",
    "gau": "Archive / URL-Historie",
    "shodan-cli": "Suchmaschinen (Drittanbieter-Index)",
    "censys-cli": "Suchmaschinen (Drittanbieter-Index)",
    "uncover": "Suchmaschinen (Drittanbieter-Index)",
    "smap": "Suchmaschinen (Drittanbieter-Index)",
    "cdncheck": "Domain / Subdomain (passiv)",
}
# Einzeln ausgeschlossene Eintraege aus den Include-Kategorien (mit Grund).
EXCLUDE_SLUGS = {
    "device-activity-tracker": "Timing-Angriff auf Messenger (PoC), kein passives OSINT",
    "telegram-nearby-map": "Geolokalisierung von Personen",
    "osintgram": "Instagram-Private-API / PII-Abgriff",
    "toutatis": "Instagram-API-Abgriff von E-Mail/Telefon",
    "ghunt": "laut Beschreibung offensives Google-Framework",
    "h8mail": "Breach-/Passwort-Hunting",
    "shadowbroker": "CCTV-/Personen-Tracking",
    "twint": "Scraping ohne API (ToS), Projekt eingestellt",
    "onionscan": "De-Anonymisierung von Hidden Services",
    "goblin": "DNS-Brute-Force",
    "shuffledns": "aktiver DNS-Brute-Force",
    "puredns": "DNS-Brute-Force",
    "dnsenum": "DNS-Brute-Force + Zonentransfer",
    "altdns": "Permutations-Brute-Force",
    "knockpy": "Wordlist-Brute-Force + Zonentransfer",
    "dnsrecon": "Zonentransfer-Versuche (aktiv gegen Ziel-DNS)",
    "subjack": "Subdomain-Takeover",
    "holehe": "nutzt Passwort-Reset-Funktionen fremder Dienste",
    "cortex": "Active-Response-Engine",
    "wazuh": "SIEM/XDR, kein OSINT",
    "snort3": "IDS/IPS, kein OSINT",
    "crowdsec": "IPS, kein OSINT",
    "grr-rapid-response": "DFIR-Agent, kein OSINT",
    "kape": "DFIR-Triage, kein OSINT",
    "osquery": "Endpoint-Telemetrie, kein OSINT",
    "sigma": "Detection-Regeln, kein OSINT",
    "thehive": "Case-Management, kein OSINT",
    "worldmonitor": "Installer via git clone && npm install (KI-Aggregation)",
    "crucix": "Installer via git clone && npm install (KI-Agent)",
    "photon": "Crawler: kontaktiert das Ziel aktiv",
    "exiflooter": "crawlt Ziel-Websites aktiv",
}
BAD_WORDS = re.compile(
    r"(?i)phish|keylog|exploit|brute|credential-theft|takeover|timing-attack|"
    r"deanonym|cctv|rat\b|c2\b|ransom|payload|wireless|deauth|password-breach"
)
SAFE_INSTALL = re.compile(r"^(sudo )?(pip3? install|pipx install|go install|apt(-get)? install|brew install)\s+[\w@./:+-]+(\s+[\w@./:+-]+)*$")


def _hint(cmd: str) -> str:
    cmd = (cmd or "").strip()
    if not cmd or any(t in cmd for t in ("|", "&&", ";", "curl", "wget", "$(", "`")):
        return ""
    return cmd if SAFE_INSTALL.match(cmd) else ""


def main(src: str) -> int:
    data = json.loads(Path(src).read_text(encoding="utf-8"))
    tools, excluded = [], []
    cats_seen = {}
    for item in data:
        slug = str(item.get("slug") or "").strip()
        cat = item.get("category")
        cats_seen[cat] = cats_seen.get(cat, 0) + 1
        if cat in INCLUDE_CATEGORIES:
            group = INCLUDE_CATEGORIES[cat]
        elif slug in EXTRA_SLUGS:
            group = EXTRA_SLUGS[slug]
        else:
            continue
        if slug in EXCLUDE_SLUGS:
            excluded.append({"slug": slug, "reason": EXCLUDE_SLUGS[slug]})
            continue
        blob = " ".join([item.get("description") or "", " ".join(item.get("tags") or [])])
        if BAD_WORDS.search(blob):
            excluded.append({"slug": slug, "reason": "Schlagwort-Filter (offensiv)"})
            continue
        gh = item.get("github") or ""
        tools.append({
            "id": f"extras-{slug}",
            "slug": slug,
            "name": item.get("name") or slug,
            "group": group,
            "source_category": cat,
            "description": (item.get("description") or "").strip()[:400],
            "website": item.get("website") or item.get("homepageUrl") or "",
            "github": f"https://github.com/{gh}" if gh and "/" in gh else "",
            "documentation": item.get("documentation") or "",
            "license": item.get("license") or "",
            "language": item.get("language") or "",
            "tags": list(item.get("tags") or [])[:8],
            "install_hint": _hint(item.get("installCommand") or ""),
            "auto_install": False,
        })
    tools.sort(key=lambda t: (t["group"], t["name"].lower()))
    excluded_cats = sorted(c for c in cats_seen if c not in INCLUDE_CATEGORIES)
    out = {
        "label": "Extras",
        "kind": "osint-catalog",
        "source": "enna src/data/tools.json (nur Daten, App nie gebaut/gestartet)",
        "source_total": len(data),
        "included_categories": sorted(INCLUDE_CATEGORIES),
        "extra_slugs": sorted(EXTRA_SLUGS),
        "excluded_categories": excluded_cats,
        "excluded_entries": excluded,
        "tools": tools,
    }
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{len(tools)} Extras-Tools -> {OUT} (ausgeschlossen: {len(excluded)} Einzel, "
          f"{len(excluded_cats)} Kategorien)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/workspace/recon/enna/src/data/tools.json"))
