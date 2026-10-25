"""Soldat elf: ELF-Binaries."""
from __future__ import annotations

from .base import Ctx, SoldierResult, first_lines, run_cli

NAME = "elf"


def run(ctx: Ctx) -> SoldierResult:
    c = ctx.classification
    d = c["details"]
    res = SoldierResult(NAME, "elf-macho-re", "ELF-Soldat")
    s = str(ctx.sample)
    info = run_cli(ctx, res, "rz-bin", ["rz-bin", "rabin2"], ["-I", s], "elf_rzbin_info.txt")
    secs = run_cli(ctx, res, "rz-bin", ["rz-bin", "rabin2"], ["-S", s], "elf_rzbin_sections.txt")
    run_cli(ctx, res, "rz-bin", ["rz-bin", "rabin2"], ["-i", s], "elf_rzbin_imports.txt")
    rl = run_cli(ctx, res, "readelf", ["readelf"], ["-h", s], "elf_readelf_header.txt")
    res.facts.update(header=d, rzbin_info=first_lines(info, 10) if info else [], sections_head=first_lines(secs, 10) if secs else [],
                     readelf_head=first_lines(rl, 6) if rl else [])
    if not (info or rl):
        res.status = "partial"
    res.warum = ("rz-bin liefert ELF-Header, Sektionen und Symbole sofort; readelf ist die Binutils-Alternative. Ghidra kommt erst danach, "
                 "wenn wir wissen, welche Architektur und welche Funktionen interessant sind. Ausgeführt wird nichts.")
    res.fund = (f"{d['class']} {d['type']} für {d['machine']} ({d['endian']}-endian), Entry-Point {d['entry']}. "
                "Der Entry-Point ist die erste Adresse, die beim Start läuft – dort beginnt die Analyse.")
    res.next = ["Entry-Point und Sektionen (.text/.data) ansehen", "Importierte Funktionen/Bibliotheken prüfen", "Funktionsliste mit rizin (aaa; afl) oder Ghidra erzeugen"]
    res.summary_de = f"ELF-Analyse: {d['machine']}, Entry {d['entry']}, Tools: {', '.join(sorted(set(res.tools_used))) or 'Python-Parser'}"
    return res
