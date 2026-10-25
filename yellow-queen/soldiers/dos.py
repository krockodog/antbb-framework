"""Soldat dos: MZ/16-Bit."""
from __future__ import annotations

from .base import Ctx, SoldierResult, run_cli

NAME = "dos"


def run(ctx: Ctx) -> SoldierResult:
    c = ctx.classification
    d = c["details"]
    res = SoldierResult(NAME, "dos-mz-16bit-re", "DOS-16-Bit-Soldat")
    run_cli(ctx, res, "rz-bin", ["rz-bin", "rabin2"], ["-I", str(ctx.sample)], "dos_rzbin_info.txt")
    res.facts.update(mz=d)
    res.warum = ("MZ-Header von Hand lesen ist bei DOS zuverlässiger als moderne Tools: sie erwarten oft 32-Bit. Daher eigener Parser, rz-bin nur als Ergänzung.")
    res.fund = (f"DOS-MZ-Programm: Start CS:IP = {d.get('cs_ip')}, Stack SS:SP = {d.get('ss_sp')}, {d.get('relocations')} Relokationen, "
                f"Headergröße {d.get('header_paragraphs')} Paragraphen. "
                + (f"Zusatz-Header {d['extended_header']} (16-Bit-Windows/DOS-Extender). " if d.get("extended_header") else "")
                + "CS:IP ist Segment:Offset – die Adresse im Real Mode ist Segment×16+Offset.")
    res.next = ["Datei als 16-Bit-Real-Mode in Ghidra/rizin laden", "Relokationstabelle auswerten (Segmentfixups)", "Laufzeit nur in DOSBox-Lab mit Oversight"]
    res.summary_de = f"DOS-MZ: CS:IP {d.get('cs_ip')}, {d.get('relocations')} Relokationen"
    return res
