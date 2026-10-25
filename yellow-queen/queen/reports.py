"""Ledger + Dossier schreiben (aus schemas/*.md-Templates, mit eingebautem Fallback)."""
from __future__ import annotations

from pathlib import Path
from string import Template
from typing import Any

from .. import config

DEFAULT_LEDGER = """---
queen_id: yellow
type: ledger
case_id: $case_id
updated_at: $updated_at
---
# Ledger – $case_id

## Run-Card
- Sample/SHA: `$sha256` ($filename)
- Class: $kind – $subtype
- Primary skill / Alternate: $primary / $alternate
- Playbook: $playbook
- Dynamic?: $dynamic
- Brain hop: $hop_chain
- Deliverables: evidence/ ledger.md dossier.md

## Completed
$completed

## Blocker
$blockers

## Next-3
$next3
"""

DEFAULT_DOSSIER = """---
queen_id: yellow
type: dossier
case_id: $case_id
sha256: $sha256
generated_at: $updated_at
---
# Dossier – $filename

## Kurzfazit
$kurzfazit

## Erklärung (Erklärbär)
$erklaerung

## Fakten (belegt)
$fakten

## Hypothesen (nicht belegt)
$hypothesen

## Evidenz
$evidenz

## Gates
$gates

## Next-3
$next3
"""


def _tpl(name: str, default: str) -> Template:
    f = config.SCHEMAS_DIR / name
    try:
        return Template(f.read_text(encoding="utf-8")) if f.exists() else Template(default)
    except OSError:
        return Template(default)


def _bul(items: list[str]) -> str:
    return "\n".join(f"- {i}" for i in items) if items else "- (keine)"


def write_ledger(case_dir: Path, case: dict[str, Any], route: Any, hops: list[dict], blockers: list[str], next3: list[str], gate_notes: list[str]) -> Path:
    completed = "\n".join(f"{i}. **{h['op']}** ({h['skill']}) – {h['summary_de']}" for i, h in enumerate(hops, 1)) or "- (noch nichts)"
    text = _tpl("ledger.md", DEFAULT_LEDGER).safe_substitute(
        case_id=case["id"], updated_at=config.now_iso(), sha256=case["sha256"], filename=case["filename"], kind=case["kind"],
        subtype=case.get("subtype", ""), primary=route.primary_skill if route else "-", alternate=route.alternate if route else "-",
        playbook=route.playbook if route else "-", dynamic=case["dynamic"], hop_chain=" → ".join(h["op"] for h in hops) or "-",
        completed=completed, blockers=_bul(blockers), next3="\n".join(f"{i}. {n}" for i, n in enumerate(next3, 1)))
    p = case_dir / "ledger.md"
    p.write_text(text, encoding="utf-8")
    return p


def write_dossier(case_dir: Path, case: dict[str, Any], classification: dict, route: Any, results: list[Any], next3: list[str], gate_notes: list[str]) -> Path:
    erkl = []
    for r in results:
        erkl.append(f"### {r.title_de}\n- **Warum dieses Tool?** {r.warum}\n- **Was bedeutet der Fund?** {r.fund}\n- **Was tun wir als Nächstes?**\n"
                    + "\n".join(f"  {i}. {n}" for i, n in enumerate(r.next, 1)))
    fakten = [f"SHA-256: `{classification['sha256']}`", f"Größe: {classification['size']} Bytes · Entropie {classification['entropy']}",
              f"Format: {classification['kind']} – {classification['subtype']} · Architektur: {classification['arch'] or '-'}",
              f"Packer-Hinweise: {', '.join(classification['packer_hints']) or 'keine'}"]
    for r in results:
        fa = ", ".join(f"{k}={str(v)[:80]}" for k, v in list(r.facts.items())[:4] if v not in (None, "", [], {}))
        fakten.append(f"{r.name}: Tools [{', '.join(sorted(set(r.tools_used))) or 'keine'}]" + (f" · {fa}" if fa else ""))
    hyp = ["Ob das Programm bösartig ist, ist NICHT bewiesen – nur statische Merkmale wurden gesammelt.",
           "Gepackt/verschlüsselt ist eine Vermutung aus Sektionsnamen/Entropie." if classification["packed"] or classification["entropy"] > 7.2 else
           "Keine Packer-Vermutung."]
    evid = [f"[{f}](evidence/{f})" for r in results for f in r.evidence]
    text = _tpl("dossier.md", DEFAULT_DOSSIER).safe_substitute(
        case_id=case["id"], sha256=case["sha256"], filename=case["filename"], updated_at=config.now_iso(),
        kurzfazit=f"{classification['kind']} ({classification['subtype'] or 'unbekannt'}), Route **{route.id}** → Skill `{route.primary_skill}`. {route.warum_de}",
        erklaerung="\n\n".join(erkl) or "(keine)", fakten=_bul(fakten), hypothesen=_bul(hyp), evidenz=_bul(evid), gates=_bul(gate_notes),
        next3="\n".join(f"{i}. {n}" for i, n in enumerate(next3, 1)))
    p = case_dir / "dossier.md"
    p.write_text(text, encoding="utf-8")
    return p
