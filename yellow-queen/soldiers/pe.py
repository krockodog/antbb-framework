"""Soldat pe: Windows-PE (native, auch gepackt)."""
from __future__ import annotations

from .base import Ctx, SoldierResult, first_lines, run_cli

NAME = "pe"


def run(ctx: Ctx) -> SoldierResult:
    c = ctx.classification
    d = c["details"]
    res = SoldierResult(NAME, "packer-unpack-re" if c["packed"] else "pe-exe-re", "PE-Windows-Soldat")
    s = str(ctx.sample)
    info = run_cli(ctx, res, "rz-bin", ["rz-bin", "rabin2"], ["-I", s], "pe_rzbin_info.txt")
    run_cli(ctx, res, "rz-bin", ["rz-bin", "rabin2"], ["-S", s], "pe_rzbin_sections.txt")
    imp = run_cli(ctx, res, "rz-bin", ["rz-bin", "rabin2"], ["-i", s], "pe_rzbin_imports.txt")
    res.facts.update(machine=c["arch"], sections=[f"{x['name']} (Entropie {x['entropy']})" for x in d.get("sections", [])],
                     entry_rva=d.get("entry_rva"), packer_hints=c["packer_hints"],
                     imports_head=first_lines(imp, 8) if imp else [], rzbin_info=first_lines(info, 8) if info else [])
    if not res.tools_used:
        res.status = "partial"
    res.warum = ("rz-bin (rizin) liest PE-Header, Sektionen und Imports in Sekunden, ohne zu disassemblieren. Alternativen: "
                 "Ghidra (gründlicher, aber langsam) oder DIE (Packer-Erkennung). Ist rz-bin nicht installiert, nutze ich meinen eingebauten PE-Parser.")
    res.fund = (f"{c['subtype']} für {c['arch']}, Einstieg (Entry-RVA) {d.get('entry_rva')}, {len(d.get('sections', []))} Sektionen. "
                + (f"ACHTUNG Packer-Hinweise: {'; '.join(c['packer_hints'])}. Das heißt: der echte Code ist verpackt, die Imports sind oft nur ein Stub. "
                   if c["packed"] else "Keine Packer-Signale in den Sektionsnamen/Entropie – das Programm ist vermutlich im Klartext analysierbar. ")
                + "Imports (Funktionen aus Windows-DLLs) zeigen, was es kann (Netzwerk, Dateien, Registry).")
    res.next = ((["Packer bestätigen (diec) und Entpackstrategie wählen"] if c["packed"] else ["Imports nach Netzwerk-/Krypto-/Persistenz-APIs filtern"])
                + ["Ghidra-Headless-Import starten (Playbook ghidra-pipeline)", "Funde mit Adresse ins Dossier übernehmen"])
    res.summary_de = f"PE-Analyse: {c['arch']}, {len(d.get('sections', []))} Sektionen, Packer={'ja' if c['packed'] else 'nein'}"
    return res
