"""Soldat hex: Intel-HEX/S-Record Firmware + 'carve' (binwalk) für Unbekanntes."""
from __future__ import annotations

from .base import Ctx, SoldierResult, first_lines, run_cli

NAME = "hex"


def _to_bin(path, out, limit=16 * 1024 * 1024):
    mem: dict[int, int] = {}
    base = 0
    for ln in path.read_text("ascii", "ignore").splitlines():
        ln = ln.strip()
        if not ln.startswith(":"):
            continue
        try:
            raw = bytes.fromhex(ln[1:])
        except ValueError:
            continue
        n, addr, t = raw[0], (raw[1] << 8) | raw[2], raw[3]
        if t == 0:
            for i in range(n):
                mem[base + addr + i] = raw[4 + i]
        elif t == 4 and n == 2:
            base = ((raw[4] << 8) | raw[5]) << 16
        elif t == 2 and n == 2:
            base = ((raw[4] << 8) | raw[5]) << 4
    if not mem:
        return False
    lo, hi = min(mem), max(mem) + 1
    if hi - lo > limit:
        return False
    buf = bytearray(b"\xff" * (hi - lo))
    for a, b in mem.items():
        buf[a - lo] = b
    out.write_bytes(bytes(buf))
    return True


def run(ctx: Ctx) -> SoldierResult:
    c = ctx.classification
    d = c["details"]
    res = SoldierResult(NAME, "hex-firmware-re", "Firmware-/HEX-Soldat")
    target = ctx.sample
    if c["subtype"] == "Intel HEX":
        binp = ctx.evidence_dir / "firmware_flat.bin"
        if _to_bin(ctx.sample, binp):
            target = binp
            res.evidence.append(binp.name)
            res.tools_used.append("python-ihex2bin")
        else:
            res.status = "partial"
    bw = run_cli(ctx, res, "binwalk", ["binwalk"], [str(target)], "hex_binwalk.txt", timeout=90)
    res.facts.update(subtype=c["subtype"], ihex=d, binwalk_head=first_lines(bw, 12) if bw else [], flat_bin=target.name)
    res.warum = ("Bei Firmware ist die Basisadresse alles: ich lese Records, Prüfsummen und Adressbereich, bevor irgendein Disassembler raten muss. "
                 "binwalk sucht danach nach eingebetteten Dateisystemen/Kompression im flachen Abbild.")
    if d.get("records"):
        res.fund = (f"{d['records']} gültige Records ({d['bad_records']} defekt), {d['data_bytes']} Datenbytes im Bereich {d['addr_min']}–{d['addr_max']}, "
                    f"EOF-Record {'vorhanden' if d['eof_record'] else 'FEHLT'}. Der Adressbereich sagt, wohin die Firmware im Chip gehört.")
    else:
        res.fund = "Container erkannt, aber kein Intel-HEX-Detail geparst (z. B. S-Record) – binwalk-Ergebnis in evidence/ ansehen."
    res.next = ["Vektortabelle/Reset-Vektor am Anfang prüfen → Architektur bestimmen", "binwalk-Funde (falls vorhanden) extrahieren", "Disassembly nur mit bestätigter Basisadresse"]
    res.summary_de = f"Firmware: {d.get('records', '?')} Records, Bereich {d.get('addr_min')}–{d.get('addr_max')}"
    return res


def run_carve(ctx: Ctx) -> SoldierResult:
    c = ctx.classification
    res = SoldierResult("carve", "re-triage", "Carving-Soldat")
    bw = run_cli(ctx, res, "binwalk", ["binwalk"], [str(ctx.sample)], "carve_binwalk.txt", timeout=90)
    res.facts.update(binwalk_head=first_lines(bw, 12) if bw else [], entropy=c["entropy"], details=c["details"])
    res.warum = "Unbekanntes Format: binwalk findet eingebettete Container/Kompression ohne dass ich ein Format erraten muss."
    res.fund = (f"Entropie {c['entropy']}. " + ("Hoch – das spricht für Verschlüsselung/Kompression. " if c["entropy"] > 7.2 else "Eher strukturierte Daten. ")
                + ("binwalk lieferte Treffer (siehe evidence/carve_binwalk.txt)." if bw and len(first_lines(bw, 6)) > 3 else "Keine eingebetteten Container gefunden bzw. binwalk fehlt."))
    res.next = ["Herkunft des Samples klären", "Falls Container: Teile einzeln neu klassifizieren"]
    res.summary_de = f"Carving: Entropie {c['entropy']}, binwalk {'genutzt' if bw is not None else 'nicht verfügbar'}"
    return res
