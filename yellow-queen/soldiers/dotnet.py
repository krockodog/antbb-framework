"""Soldat dotnet: .NET-Assemblies (CLR)."""
from __future__ import annotations

from .base import Ctx, SoldierResult, first_lines, py_strings, run_cli

NAME = "dotnet"
OBF_HINTS = [b"ConfuserEx", b"Eazfuscator", b"SmartAssembly", b"Dotfuscator", b"Babel", b"Agile.NET", b"Obfuscated by"]


def run(ctx: Ctx) -> SoldierResult:
    c = ctx.classification
    d = c["details"]
    res = SoldierResult(NAME, "dotnet-re", ".NET-Soldat")
    data = ctx.sample.read_bytes()[:32 * 1024 * 1024]
    obf = [h.decode() for h in OBF_HINTS if h in data]
    info = run_cli(ctx, res, "rz-bin", ["rz-bin", "rabin2"], ["-I", str(ctx.sample)], "dotnet_rzbin_info.txt")
    ver = [s for s in py_strings(data, 4, 4000) if s.startswith("v4.0.") or s.startswith("v2.0.")][:1]
    res.facts.update(clr=True, runtime=ver[0] if ver else "unbekannt", obfuscator_hints=obf, rzbin_info=first_lines(info, 8) if info else [],
                     ilspy_hint="ilspycmd/dnSpy auf Windows nutzen (nicht Teil dieses Soldaten)")
    res.warum = ("Der CLR-Header (Data-Directory 14) ist gesetzt – das ist .NET. Daher kein nativer Decompiler: ILSpy/dnSpy rekonstruieren C# nahezu verlustfrei. "
                 "Ich prüfe hier nur Metadaten und Obfuscator-Spuren.")
    res.fund = (f".NET-Assembly ({c['arch']}), Runtime-Hinweis: {res.facts['runtime']}. "
                + (f"Obfuscator-Spuren: {', '.join(obf)} – Namen im Code sind evtl. unlesbar. " if obf else "Keine bekannten Obfuscator-Strings gefunden. ")
                + "Das heißt: Klassen/Methoden-Namen sind wahrscheinlich noch lesbar.")
    res.next = ["Assembly in ILSpy/dnSpy öffnen und Namespaces auflisten", "Ressourcen und eingebettete Dateien prüfen", "Bei Obfuscator: de4dot-Strategie im Lab planen"]
    res.summary_de = f".NET-Analyse: Runtime {res.facts['runtime']}, Obfuscator-Hinweise: {len(obf)}"
    return res
