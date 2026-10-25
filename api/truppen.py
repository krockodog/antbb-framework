"""Serverseitig gerenderte Truppenübersicht (/truppen).

Quellen je Königin:
- Soldaten: store.queen_detail(q)["soldiers"] (echte Registry, Fallback = Seed).
- Skills: antbb-Registry build_registry (specialty + skill-Name + role) für
  Rot/Blau; Yellow-REGISTRY mit lokaler Spezialitäten-Karte.
- Playbooks: Hub-Katalog playbook_map(q) (Titel + kind). Echte Registry-
  Soldaten ohne Hub-Zuordnung zeigen stattdessen ihre Registry-Playbooks
  (Name + Mode).

Läuft auch ohne importierbare Registry — dann fallen Rot/Blau auf den
Seed-Katalog zurück und Yellow auf die REGISTRY-Fallbackliste.
"""

from __future__ import annotations

from html import escape

from api.catalog import QUEEN_IDS, playbook_map

ACCENT = {"red": "#ff6b6b", "blue": "#5aa2ff", "yellow": "#ffd75a"}

# Spezialitäten der Gelben RE-Soldaten (aus yellow_queen/soldiers/*.py
# abgeleitet; die REGISTRY selbst führt nur Funktionsnamen).
YELLOW_SKILLS = {
    "triage": ("re-triage", "Triage-Soldat", "file/strings/xxd/diec – Dateityp, Strings, Packer-Hinweise"),
    "pe": ("pe-exe-re", "PE-Windows-Soldat", "PE-Header, Sektionen, Imports, Packer (rz-bin/rizin)"),
    "dotnet": ("dotnet-re", ".NET-Soldat", ".NET-Assemblies (CLR)"),
    "android": ("apk-android-re", "Android-Soldat", "APK/DEX – Manifest/Code via apktool + jadx"),
    "elf": ("elf-macho-re", "ELF-Soldat", "ELF-Binaries"),
    "hex": ("hex-firmware-re", "Firmware-/HEX-Soldat", "Intel-HEX/S-Record Firmware"),
    "carve": ("re-triage", "Carving-Soldat", "binwalk-Carving für unbekannte Proben"),
    "dos": ("dos-mz-16bit-re", "DOS-16-Bit-Soldat", "MZ/16-Bit"),
    "dynamic": ("dynamic-lab-re", "Dynamic-Lab-Soldat", "Lab-Lauf mit Oversight (frida-lab)"),
}


def _registry_index() -> dict[str, dict]:
    """name -> Registry-Soldat (specialty, role, playbooks, skill). Leer bei Fehler."""
    try:
        from api.real_queens import _ensure_colony_path, _registry_soldiers

        _ensure_colony_path()
        soldiers = _registry_soldiers(include_blue=True)
    except Exception:  # noqa: BLE001
        return {}
    index: dict[str, dict] = {}
    for item in soldiers or []:
        name = item.get("name")
        if name:
            index[str(name)] = item
    return index


def _yellow_ids() -> list[str]:
    try:
        from api.real_queens import _yellow_soldiers

        ids = _yellow_soldiers()
        return list(ids) if ids else []
    except Exception:  # noqa: BLE001
        return ["triage", "pe", "dotnet", "android", "elf", "hex", "dos", "dynamic"]


def truppen_data(store) -> list[dict]:
    """Je Queen eine Sektion mit Soldaten-Zeilen + Playbook-Liste."""
    index = _registry_index()
    sections: list[dict] = []
    for queen in QUEEN_IDS:
        detail = store.queen_detail(queen)
        hub_books = playbook_map(queen)
        rows: list[dict] = []
        for soldier in detail.get("soldiers") or []:
            name = str(soldier.get("name") or soldier.get("soldier_id") or "?")
            reg = index.get(name) if index else None
            skill_lines: list[str] = []
            books: list[tuple[str, str]] = []
            if reg is not None:
                specialty = str(reg.get("specialty") or name)
                skill = reg.get("skill") or {}
                skill_name = str(skill.get("name") or specialty)
                skill_lines.append(f"{specialty} · {skill_name}")
                role = str(reg.get("role") or "").strip()
                if role:
                    skill_lines.append(role)
                books = [
                    (str(pb.get("name") or "?"), str(pb.get("mode") or "playbook"))
                    for pb in (reg.get("playbooks") or [])
                ]
            else:
                role = str(soldier.get("role") or "").strip()
                if role:
                    skill_lines.append(role)
                if soldier.get("stub_note") and not skill_lines:
                    skill_lines.append(str(soldier["stub_note"]))
                for pid in soldier.get("playbook_ids") or []:
                    book = hub_books.get(pid)
                    if book:
                        books.append((str(book["title"]), str(book["kind"])))
            rows.append({"name": name, "skills": skill_lines, "playbooks": books})

        if queen == "yellow":
            # Echte RE-Soldaten aus der Yellow-Registry vor den Hub-Seed-Soldaten.
            seed_names = {row["name"] for row in rows}
            real_rows: list[dict] = []
            for soldier_id in _yellow_ids():
                key, title, desc = YELLOW_SKILLS.get(
                    soldier_id, (soldier_id, f"{soldier_id}-Soldat", "RE-Soldat")
                )
                real_rows.append({
                    "name": soldier_id,
                    "skills": [f"{key} · {title}", desc],
                    "playbooks": [],
                })
            rows = [r for r in real_rows if r["name"] not in seed_names] + rows

        sections.append({
            "queen_id": queen,
            "queen_name": str(detail.get("name") or queen),
            "soldier_count": len(rows),
            "playbooks": [
                (str(book["title"]), str(book["kind"]))
                for book in detail.get("playbooks") or []
            ],
            "rows": rows,
        })
    return sections


_PAGE_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 28px 20px 48px;
  background: #0d1117; color: #d7dde6;
  font: 14px/1.5 "Segoe UI", system-ui, sans-serif;
}
.wrap { max-width: 1180px; margin: 0 auto; }
header.page { display: flex; flex-wrap: wrap; align-items: baseline; gap: 10px 18px; margin-bottom: 6px; }
header.page h1 { font-size: 22px; margin: 0; color: #f0f3f7; letter-spacing: .4px; }
header.page .sub { color: #8b95a3; font-size: 13px; }
nav.top { margin: 10px 0 26px; display: flex; gap: 8px; flex-wrap: wrap; }
nav.top a {
  color: #cfd6df; text-decoration: none; border: 1px solid #2b3442;
  border-radius: 6px; padding: 4px 12px; font-size: 13px; background: #141a23;
}
nav.top a:hover { border-color: #4a576a; color: #fff; }
section.queen {
  border: 1px solid #232c3a; border-radius: 10px; margin-bottom: 26px;
  background: #10151d; overflow: hidden;
}
section.queen h2 {
  margin: 0; padding: 12px 18px; font-size: 16px; color: #f0f3f7;
  border-bottom: 1px solid #232c3a; border-left: 4px solid var(--accent);
}
section.queen .meta { padding: 8px 18px 0; color: #8b95a3; font-size: 12.5px; }
table { width: 100%; border-collapse: collapse; margin: 10px 0 0; }
th, td { text-align: left; vertical-align: top; padding: 7px 18px; }
th { color: #8b95a3; font-size: 11.5px; text-transform: uppercase; letter-spacing: .8px;
     border-bottom: 1px solid #232c3a; font-weight: 600; }
td { border-bottom: 1px solid #1a2230; font-size: 13.5px; }
tr:last-child td { border-bottom: none; }
td.name { color: #f0f3f7; font-weight: 600; white-space: nowrap; }
td.skills .main { color: var(--accent); font-weight: 600; }
td.skills .sub { color: #8b95a3; font-size: 12px; display: block; max-width: 520px; }
td.books ul { margin: 0; padding-left: 16px; }
td.books li { margin: 1px 0; }
td.books .kind { color: #8b95a3; font-size: 11.5px; }
.books-block { padding: 10px 18px 16px; }
.books-block h3 { margin: 6px 0 8px; font-size: 12px; color: #8b95a3;
  text-transform: uppercase; letter-spacing: .8px; }
.books-block ul { margin: 0; padding-left: 18px; columns: 2; column-gap: 34px; }
.books-block li { margin: 2px 0; font-size: 13px; break-inside: avoid; }
.books-block .kind { color: #8b95a3; font-size: 11.5px; }
footer.page { margin-top: 28px; color: #5b6572; font-size: 12px; }
@media (max-width: 760px) { .books-block ul { columns: 1; } td.skills .sub { max-width: none; } }
"""


def render_truppen(store) -> str:
    sections = truppen_data(store)
    parts: list[str] = [
        "<!doctype html><html lang=\"de\"><head>",
        "<meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "<title>Truppen · All and One</title>",
        f"<style>{_PAGE_CSS}</style>",
        "</head><body><div class=\"wrap\">",
        "<header class=\"page\"><h1>Truppenübersicht</h1>",
        "<span class=\"sub\">All and One · alle Soldaten der drei Königinnen</span></header>",
        "<nav class=\"top\">",
        "<a href=\"/\">Start</a><a href=\"/red\">Rote Königin</a>",
        "<a href=\"/blue\">Blaue Königin</a><a href=\"/yellow\">Gelbe Königin</a>",
        "</nav>",
    ]
    for section in sections:
        accent = ACCENT[section["queen_id"]]
        parts.append(
            f"<section class=\"queen\" style=\"--accent:{accent}\">"
            f"<h2>{escape(section['queen_name'])}</h2>"
            f"<div class=\"meta\">{section['soldier_count']} Soldaten · "
            f"{len(section['playbooks'])} Playbooks</div>"
        )
        parts.append(
            "<table><thead><tr><th>Soldat</th>"
            "<th>Spezialität / Skills</th><th>Playbooks</th></tr></thead><tbody>"
        )
        for row in section["rows"]:
            skills = ""
            if row["skills"]:
                main = escape(row["skills"][0])
                rest = "".join(
                    f'<span class="sub">{escape(line)}</span>' for line in row["skills"][1:]
                )
                skills = f'<span class="main">{main}</span>{rest}'
            if row["playbooks"]:
                items = "".join(
                    f"<li>{escape(title)} <span class=\"kind\">({escape(kind)})</span></li>"
                    for title, kind in row["playbooks"]
                )
                books = f"<ul>{items}</ul>"
            else:
                books = '<span class="kind">–</span>'
            parts.append(
                f'<tr><td class="name">{escape(row["name"])}</td>'
                f'<td class="skills">{skills}</td><td class="books">{books}</td></tr>'
            )
        parts.append("</tbody></table>")
        if section["playbooks"]:
            items = "".join(
                f"<li>{escape(title)} <span class=\"kind\">({escape(kind)})</span></li>"
                for title, kind in section["playbooks"]
            )
            parts.append(
                f'<div class="books-block"><h3>Playbooks dieser Königin '
                f"(Titel + Kind)</h3><ul>{items}</ul></div>"
            )
        parts.append("</section>")
    parts.append(
        '<footer class="page">Quellen: antbb-Registry (build_registry), '
        "yellow_queen/soldiers/REGISTRY, Hub-Katalog api/catalog.py. "
        "Fallback: Seed-Katalog, falls eine Registry nicht importierbar ist."
        "</footer></div></body></html>"
    )
    return "".join(parts)
