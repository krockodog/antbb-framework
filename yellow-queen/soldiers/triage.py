"""Soldat triage: file, strings, xxd, diec – mit Python-Fallbacks."""
from __future__ import annotations

import re

from ..redact import redact
from .base import Ctx, SoldierResult, first_lines, hexdump, py_strings, run_cli

NAME = "triage"
URL_RX = re.compile(r"https?://[^\s\"'<>]{4,80}")
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def run(ctx: Ctx) -> SoldierResult:
    c = ctx.classification
    res = SoldierResult(NAME, "re-triage", "Triage-Soldat")
    data = ctx.sample.read_bytes()[:16 * 1024 * 1024]

    ft = run_cli(ctx, res, "file", ["file"], ["-b", str(ctx.sample)], "triage_file.txt")
    res.facts["file"] = first_lines(ft, 1)[0] if ft and first_lines(ft, 1) else c["magic"] or "(interne Magic-Erkennung)"

    st = run_cli(ctx, res, "strings", ["strings"], ["-a", "-n", "6", str(ctx.sample)], "triage_strings.txt")
    if st is None:
        lines = [redact(s) for s in py_strings(data)]
        (ctx.evidence_dir / "triage_strings.txt").write_text("\n".join(lines), encoding="utf-8")
        res.tools_used.append("python-strings")
        res.evidence.append("triage_strings.txt")
        strings = lines
    else:
        strings = st.splitlines()
    joined = "\n".join(strings[:20000])
    urls = sorted(set(URL_RX.findall(joined)))[:15]
    ips = sorted(set(IP_RX.findall(joined)))[:15]
    res.facts.update(strings_count=len(strings), urls=[redact(u) for u in urls], ips=ips)

    xd = run_cli(ctx, res, "xxd", ["xxd"], ["-l", "256", str(ctx.sample)], "triage_head.hex")
    if xd is None:
        xd = hexdump(data)
        (ctx.evidence_dir / "triage_head.hex").write_text(xd, encoding="utf-8")
        res.tools_used.append("python-hexdump")
        res.evidence.append("triage_head.hex")
    ascii_head = "".join(chr(b) if 32 <= b < 127 else " " for b in data[:256])
    if redact(ascii_head) != ascii_head:  # Secrets nie speichern – auch nicht im Hexdump
        (ctx.evidence_dir / "triage_head.hex").write_text("[Hexdump unterdrückt: Kopfbereich enthält mögliche Secrets]", encoding="utf-8")

    de = run_cli(ctx, res, "diec", ["diec"], [str(ctx.sample)], "triage_diec.txt")
    if de:
        res.facts["diec"] = first_lines(de, 6)

    res.warum = ("Zuerst Fakten statt Raten: sha256 + Dateityp + Strings + Hex-Kopf sind billig, ungefährlich (nichts wird ausgeführt) "
                 "und entscheiden, welches schwere Werkzeug (Ghidra/jadx) sich lohnt. Alternative wäre direkt ein Decompiler – "
                 "der liefert aber bei falschem Format nur Müll.")
    res.fund = (f"Format laut Magic: {c['kind']} – {c['subtype'] or 'unbekannt'}. {len(strings)} lesbare Strings"
                f"{', ' + str(len(urls)) + ' URL(s)' if urls else ''}{', ' + str(len(ips)) + ' IP-artige Werte' if ips else ''}. "
                f"Entropie {c['entropy']} (über ~7,2 = vermutlich gepackt/verschlüsselt).")
    res.next = ["Fachspezifischen Soldaten der Route laufen lassen", "Auffällige Strings mit Adresse/Offset im Dossier festhalten"]
    res.summary_de = f"Triage: {c['kind']} · {len(strings)} Strings · Tools: {', '.join(res.tools_used) or 'keine'}"
    return res
