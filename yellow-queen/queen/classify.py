"""Phase 1 – Classify: sha256 + Magic + Packer/.NET-Hinweise (reines Python, keine Ausführung)."""
from __future__ import annotations

import hashlib
import math
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".winlice": "Themida/WinLicense", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack", "MPRESS1": "MPRESS", "MPRESS2": "MPRESS",
    ".enigma1": "Enigma", ".enigma2": "Enigma", ".mpress": "MPRESS",
}
PE_MACHINES = {0x14c: "x86 (i386)", 0x8664: "x64 (AMD64)", 0x1c0: "ARM", 0xaa64: "ARM64", 0x200: "IA-64", 0x1c4: "ARMNT"}
ELF_MACHINES = {2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V", 94: "Xtensa", 247: "eBPF"}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in counts if c), 3)


def hashes(path: Path) -> tuple[str, str, int]:
    sha, md = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            sha.update(chunk)
            md.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), md.hexdigest(), size


def parse_pe(d: bytes) -> dict[str, Any] | None:
    if len(d) < 64 or d[:2] != b"MZ":
        return None
    lfa = struct.unpack_from("<I", d, 0x3C)[0]
    if lfa + 24 > len(d) or d[lfa:lfa + 4] != b"PE\0\0":
        return None
    try:
        machine, nsec, _ts, _p, _n, optsize, chars = struct.unpack_from("<HHIIIHH", d, lfa + 4)
        opt = lfa + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        plus = magic == 0x20B
        entry = struct.unpack_from("<I", d, opt + 16)[0]
        ddir = opt + (112 if plus else 96)
        clr_rva = struct.unpack_from("<II", d, ddir + 14 * 8)[0] if optsize >= (112 if plus else 96) + 15 * 8 else 0
        subsystem = struct.unpack_from("<H", d, opt + 68)[0]
        secs = []
        so = opt + optsize
        for i in range(min(nsec, 96)):
            o = so + i * 40
            if o + 40 > len(d):
                break
            name = d[o:o + 8].rstrip(b"\0").decode("latin-1", "replace")
            vsize, vrva, rsize, rptr = struct.unpack_from("<IIII", d, o + 8)
            sch = struct.unpack_from("<I", d, o + 36)[0]
            ent = entropy(d[rptr:rptr + rsize]) if rsize and rptr < len(d) else 0.0
            secs.append({"name": name, "vsize": vsize, "rsize": rsize, "entropy": ent, "exec": bool(sch & 0x20000000)})
        return {"machine": PE_MACHINES.get(machine, hex(machine)), "pe32plus": plus, "dll": bool(chars & 0x2000),
                "entry_rva": hex(entry), "subsystem": subsystem, "dotnet": clr_rva != 0, "sections": secs}
    except struct.error:
        return None


def parse_mz(d: bytes) -> dict[str, Any] | None:
    if len(d) < 28 or d[:2] not in (b"MZ", b"ZM"):
        return None
    last, pages, nreloc, hdrpar, _mina, _maxa, ss, sp, csum, ip, cs = struct.unpack_from("<11H", d, 2)
    ext = None
    if len(d) >= 0x40:
        lfa = struct.unpack_from("<I", d, 0x3C)[0]
        if 0 < lfa < len(d) - 2 and d[lfa:lfa + 2] in (b"NE", b"LE", b"LX"):
            ext = d[lfa:lfa + 2].decode()
    size = ((pages - 1) * 512 + (last or 512)) if pages else 0
    return {"header_paragraphs": hdrpar, "relocations": nreloc, "cs_ip": f"{cs:04X}:{ip:04X}", "ss_sp": f"{ss:04X}:{sp:04X}",
            "declared_size": size, "extended_header": ext, "checksum": csum}


def parse_elf(d: bytes) -> dict[str, Any] | None:
    if len(d) < 20 or d[:4] != b"\x7fELF":
        return None
    cls = {1: "ELF32", 2: "ELF64"}.get(d[4], "ELF?")
    end = "<" if d[5] == 1 else ">"
    etype, machine = struct.unpack_from(end + "HH", d, 16)
    entry = 0
    try:
        entry = struct.unpack_from(end + ("Q" if d[4] == 2 else "I"), d, 24)[0]
    except struct.error:
        pass
    return {"class": cls, "endian": "little" if d[5] == 1 else "big",
            "type": {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(etype, str(etype)),
            "machine": ELF_MACHINES.get(machine, str(machine)), "entry": hex(entry)}


def parse_ihex(d: bytes) -> dict[str, Any] | None:
    try:
        text = d[:4_000_000].decode("ascii")
    except UnicodeDecodeError:
        return None
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2 or not lines[0].startswith(":"):
        return None
    ok = bad = databytes = 0
    base = 0
    lo, hi = None, None
    eof = False
    for ln in lines:
        if not re.fullmatch(r":[0-9A-Fa-f]{10,}", ln) or len(ln) % 2 == 0:
            bad += 1
            continue
        raw = bytes.fromhex(ln[1:])
        if sum(raw) & 0xFF != 0 or raw[0] != len(raw) - 5:
            bad += 1
            continue
        ok += 1
        n, addr, rtype = raw[0], (raw[1] << 8) | raw[2], raw[3]
        if rtype == 0:
            a = base + addr
            lo = a if lo is None else min(lo, a)
            hi = a + n if hi is None else max(hi, a + n)
            databytes += n
        elif rtype == 4 and n == 2:
            base = ((raw[4] << 8) | raw[5]) << 16
        elif rtype == 2 and n == 2:
            base = ((raw[4] << 8) | raw[5]) << 4
        elif rtype == 1:
            eof = True
    if ok < 2 or ok < bad:
        return None
    return {"records": ok, "bad_records": bad, "data_bytes": databytes,
            "addr_min": hex(lo) if lo is not None else None, "addr_max": hex(hi) if hi is not None else None, "eof_record": eof}


def parse_srec(d: bytes) -> bool:
    try:
        t = d[:2000].decode("ascii")
    except UnicodeDecodeError:
        return False
    ls = [x.strip() for x in t.splitlines() if x.strip()]
    return len(ls) >= 2 and all(re.fullmatch(r"S[0-9][0-9A-Fa-f]{4,}", x) for x in ls[:3])


def parse_apk(path: Path) -> dict[str, Any] | None:
    if not zipfile.is_zipfile(path):
        return None
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        info = {"entries": len(names), "has_manifest": "AndroidManifest.xml" in names,
                "dex": sorted(n for n in names if re.fullmatch(r"classes\d*\.dex", n)),
                "native_libs": sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2}),
                "signed": any(n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC")) for n in names)}
    info["is_apk"] = info["has_manifest"] and bool(info["dex"])
    return info


def classify(path: Path) -> dict[str, Any]:
    sha, md5, size = hashes(path)
    with open(path, "rb") as f:
        head = f.read(8 * 1024 * 1024)
    out: dict[str, Any] = {"sha256": sha, "md5": md5, "size": size, "entropy": entropy(head), "kind": "UNKNOWN",
                           "subtype": "", "arch": "", "packed": False, "packer_hints": [], "details": {}, "magic": ""}
    pe = parse_pe(head)
    elf = parse_elf(head)
    if pe:
        out.update(kind="DOTNET" if pe["dotnet"] else "PE", arch=pe["machine"],
                   subtype=("DLL" if pe["dll"] else "EXE") + (" (PE32+)" if pe["pe32plus"] else " (PE32)") + (" · .NET/CLR" if pe["dotnet"] else ""),
                   details=pe, magic="MZ + PE-Signatur")
        for s in pe["sections"]:
            if s["name"] in PACKER_SECTIONS:
                out["packer_hints"].append(f"Sektion {s['name']} → {PACKER_SECTIONS[s['name']]}")
            elif s["entropy"] > 7.3 and s["rsize"] > 2048 and s["exec"]:
                out["packer_hints"].append(f"Ausführbare Sektion {s['name']} hat Entropie {s['entropy']} (verdächtig hoch)")
        out["packed"] = bool(out["packer_hints"])
    elif elf:
        out.update(kind="ELF", arch=elf["machine"], subtype=f"{elf['class']} {elf['type']} ({elf['endian']}-endian)", details=elf, magic="\\x7fELF")
    elif head[:2] in (b"MZ", b"ZM"):
        mz = parse_mz(head)
        out.update(kind="DOS", subtype="MZ (DOS/16-bit)" + (f" mit {mz['extended_header']}-Header" if mz and mz["extended_header"] else ""),
                   arch="x86 (16-bit)", details=mz or {}, magic="MZ ohne PE-Signatur")
    elif head[:4] == b"dex\n":
        out.update(kind="APK", subtype="Roh-DEX (Dalvik)", details={"is_apk": False, "dex_only": True, "version": head[4:7].decode("latin-1")}, magic="dex\\n")
    elif head[:4] == b"PK\x03\x04":
        apk = parse_apk(path)
        if apk and apk["is_apk"]:
            out.update(kind="APK", subtype="Android-Paket (ZIP + classes.dex)", details=apk, magic="PK + AndroidManifest.xml + classes.dex")
        else:
            out.update(kind="UNKNOWN", subtype="ZIP-Container (kein APK)", details=apk or {}, magic="PK")
    else:
        ih = parse_ihex(head)
        if ih:
            out.update(kind="HEX", subtype="Intel HEX", details=ih, magic="':' Records mit gültiger Prüfsumme")
        elif parse_srec(head):
            out.update(kind="HEX", subtype="Motorola S-Record", details={}, magic="S-Records")
    return out
