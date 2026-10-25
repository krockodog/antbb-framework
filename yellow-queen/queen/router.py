"""Phase 2 – Entscheidungsbaum: Klassifikation → Primär-Skill, Alternative, Soldaten, Playbook."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Route:
    id: str
    primary_skill: str
    alternate: str
    soldiers: list[str]
    playbook: str
    warum_de: str
    nicht_zuerst_de: str
    next_de: list[str] = field(default_factory=list)


def decide(c: dict) -> Route:
    kind, packed = c["kind"], c.get("packed")
    if kind == "PE" and packed:
        return Route("PE-PACKED", "packer-unpack-re", "pe-exe-re", ["triage", "pe"], "pe-windows",
                     "Packer-Hinweise gefunden: erst entpacken (oder zumindest verstehen), sonst sieht der Decompiler nur Packer-Code.",
                     "Ghidra direkt auf die gepackte Datei", ["Packer mit DIE bestätigen", "Entpacken im Lab (nur mit Oversight) oder statisch Unpacker-Stub lesen", "Danach pe-exe-re erneut laufen lassen"])
    if kind == "PE":
        return Route("PE", "pe-exe-re", "ghidra-pipeline", ["triage", "pe"], "pe-windows",
                     "Natives Windows-Programm: Header, Sektionen und Imports verraten schnell, was das Programm kann – bevor wir tief decompilieren.",
                     "Dynamic/Ausführung", ["Imports nach Auffälligkeiten durchsehen", "Ghidra-Headless-Import für Funktionsliste", "Interessante Strings zu Adressen zuordnen"])
    if kind == "DOTNET":
        return Route("DOTNET", "dotnet-re", "pe-exe-re", ["triage", "dotnet"], "hexgrab-dotnet",
                     "Das ist .NET (CLR-Header vorhanden): IL lässt sich fast verlustfrei zurück in C# übersetzen – Ghidra auf nativem Code wäre hier der falsche Weg.",
                     "Ghidra für native Maschinencode-Analyse", ["Mit ILSpy/dnSpy (Windows) Assembly öffnen", "Obfuscator prüfen (DIE)", "Namespaces/Ressourcen auflisten"])
    if kind == "APK":
        return Route("APK", "apk-android-re", "native-ghidra", ["triage", "android"], "ui-kit-extract",
                     "Android-App: Manifest (Berechtigungen/Einstiegspunkte) und Java-Code über jadx/apktool sind der schnellste Überblick; native Libs kommen danach.",
                     "Native .so ohne JADX-Karte", ["Manifest: Berechtigungen und Activities lesen", "jadx-Quelltext nach Einstiegspunkten durchsuchen", "Native Libs (lib/) gezielt mit Ghidra/rizin"])
    if kind == "ELF":
        return Route("ELF", "elf-macho-re", "ghidra-pipeline", ["triage", "elf"], "native-r2-cutter",
                     "ELF-Binary: rizin/rz-bin zeigt Header, Sektionen und Symbole sehr schnell; Ghidra ist die zweite Stufe für tiefe Analyse.",
                     "Dynamic/Ausführung", ["Entry-Point und Sektionen prüfen", "Symbole/Imports ansehen", "Funktionen mit rizin (aaa; afl) oder Ghidra listen"])
    if kind == "HEX":
        return Route("HEX", "hex-firmware-re", "binwalk", ["triage", "hex"], "firmware-hex",
                     "Intel-HEX/S-Record ist ein Firmware-Abbild: wir prüfen Adressbereich und Prüfsummen, bevor wir irgendeine Basisadresse raten.",
                     "Stilles Disassemblieren mit geratener Basisadresse", ["Adressbereich/Lücken bestätigen", "Binärabbild extrahieren und mit binwalk scannen", "Architektur anhand Vektortabelle bestimmen"])
    if kind == "DOS":
        return Route("DOS", "dos-mz-16bit-re", "ghidra-pipeline", ["triage", "dos"], "dxball-style",
                     "MZ ohne PE-Signatur ist ein DOS-/16-Bit-Programm: andere Annahmen (Segmente, Real Mode) als bei 32-Bit.",
                     "32-Bit-Annahmen und Standard-Decompiler-Einstellungen", ["CS:IP und Relokationen prüfen", "Als 16-bit real-mode in Ghidra/rizin laden", "Spätere Laufzeit-Tests nur in DOSBox-Lab"])
    return Route("UNKNOWN", "re-triage", "hex-firmware-re", ["triage", "carve"], "none",
                 "Format nicht erkannt: wir sammeln erst Fakten (Strings, Entropie, eingebettete Container), bevor wir ein Werkzeug festlegen.",
                 "Decompiler auf unbekannte Daten", ["Eingebettete Dateien mit binwalk prüfen", "Hoher Entropiewert → verschlüsselt/komprimiert?", "Herkunft des Samples klären und neu einordnen"])
