"""Next-3 / Findings / Bypass – strukturierte Flow-Daten für UI + Brain-Snapshot."""
from __future__ import annotations

from typing import Any

from .. import config


def _step(i: int, label: str, status: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": f"n{i}",
        "idx": i,
        "label": label,
        "status": status,  # pending | active | done | blocked
        "progress": f"{i}/3",
        "warum": extra.get("warum", ""),
        "fund": extra.get("fund", ""),
        "next": extra.get("next") or [],
        "tool": extra.get("tool", ""),
        "jetzt": status == "active",
    }


def build_next3(
    route: Any | None,
    classification: dict | None,
    results: list[Any],
    hops: list[dict],
    finished: bool,
    phase: str = "idle",
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Baut 3 strukturierte Next-Schritte + active_step.

    Beispiel-Flow PE-PACKED: Packer/DIE → Bypass/Ghidra → Dossier.
    Status: erledigte Hops → done; erster offener → active („Jetzt“); Rest pending.
    """
    labels = _labels_for_route(route, classification)
    # Heuristik: welche Schritte schon „berührt“ wurden
    hop_ops = " ".join(h.get("op", "") + " " + h.get("skill", "") for h in hops).lower()
    hop_text = " ".join(
        (h.get("summary_de", "") + " " + h.get("fund", "") + " " + " ".join(h.get("next") or []))
        for h in hops
    ).lower()
    tools_used = {t for r in results for t in (r.tools_used or [])}
    facts_blob = " ".join(str(r.facts) for r in results).lower()
    evidence = {f for r in results for f in (r.evidence or [])}
    packed = bool(classification and classification.get("packed"))

    done_flags = [False, False, False]
    # Schritt 1: DIE / Packer / Triage / Classify
    if any(x in tools_used for x in ("diec", "file", "strings", "python-strings")) or "classify" in hop_ops or "soldier:triage" in hop_ops:
        done_flags[0] = True
    if "die" in labels[0].lower() and ("diec" in tools_used or "diec" in facts_blob or "triage_diec" in " ".join(evidence)):
        done_flags[0] = True
    # Schritt 2: Ghidra / r2 / Soldat / Bypass-Arbeit
    if any(x in hop_ops for x in ("soldier:pe", "soldier:elf", "soldier:dotnet", "soldier:android", "soldier:dos", "soldier:hex")):
        done_flags[1] = True
    if "ghidra" in hop_text or "rz-bin" in tools_used or "rabin2" in tools_used:
        done_flags[1] = True
    # Schritt 3: Dossier / Merge
    if "merge" in hop_ops or finished:
        done_flags[2] = True

    # Während des Laufs: aktiver Orchestrierungs-Schritt steuert „Jetzt“
    active_idx: int | None = None
    if not finished:
        if phase in ("triage",) and not done_flags[0]:
            active_idx = 1
        elif phase in ("static", "reconstruct", "dynamic") and not done_flags[1]:
            active_idx = 2 if done_flags[0] else 1
        elif phase == "merge":
            active_idx = 3
        else:
            # erster nicht fertiger
            for i, d in enumerate(done_flags, 1):
                if not d:
                    active_idx = i
                    break
    else:
        # Nach Merge: Next-3 = weiterführende Arbeit; Schritt 3 (Dossier) ist done,
        # Schritt 1+2 aus dem Route-Plan ggf. noch offen als „Jetzt“
        # Für die UI nach Lauf: zeige die 3 Route-Next als Folgeplan.
        # Neu bewerten: Dossier ist geschrieben → step3 done; frühere aus Heuristik.
        pass

    steps: list[dict[str, Any]] = []
    for i, label in enumerate(labels, 1):
        if done_flags[i - 1]:
            status = "done"
        elif active_idx == i:
            status = "active"
        else:
            status = "pending"
        # Packer-Bypass als blocked wenn Oversight fehlt und Label entpacken meint
        if packed and i == 2 and "entpack" in label.lower() and not finished:
            # bleibt pending/active; blocked kommt aus bypass-Objekt
            pass
        detail = _detail_for_step(i, label, route, classification, results, hops)
        steps.append(_step(i, label, status, **detail))

    # Sicherstellen: genau ein „Jetzt“, wenn noch etwas offen
    actives = [s for s in steps if s["status"] == "active"]
    if not actives:
        for s in steps:
            if s["status"] == "pending":
                s["status"] = "active"
                s["jetzt"] = True
                break
    else:
        for s in steps:
            s["jetzt"] = s["status"] == "active"

    active_step = next((s for s in steps if s["status"] == "active"), None)
    if finished and all(s["status"] == "done" for s in steps):
        # Folgeplan: Route-Next als neue pending mit erstem „Jetzt“
        # behalten wir die done-Markierung – Judith sieht Fortschritt 3/3
        active_step = None
        for s in steps:
            s["jetzt"] = False
    return steps, active_step


def _labels_for_route(route: Any | None, classification: dict | None) -> list[str]:
    if route and getattr(route, "next_de", None):
        labels = list(route.next_de[:3])
    else:
        labels = ["Classify / Triage", "Toolchain / Soldat", "Dossier schreiben"]
    while len(labels) < 3:
        labels.append(["Vertiefen", "Evidence sichern", "Dossier aktualisieren"][len(labels)])
    # Eye-catcher-Labels für PE-PACKED angleichen an Judith-Beispiel
    packed = bool(classification and classification.get("packed"))
    rid = getattr(route, "id", "") if route else ""
    if rid == "PE-PACKED" or (packed and (classification or {}).get("kind") == "PE"):
        labels = [
            "Packer/DIE bestätigen",
            "Bypass/Entpacken → dann Ghidra-Headless",
            "Funde mit Adresse ins Dossier",
        ]
    elif rid == "PE":
        labels = [
            "Packer/DIE prüfen (Triage)",
            "Ghidra-Headless / Imports (rz-bin)",
            "Funde mit Adresse ins Dossier",
        ]
    return labels[:3]


def _detail_for_step(
    i: int, label: str, route: Any | None, classification: dict | None,
    results: list[Any], hops: list[dict],
) -> dict[str, Any]:
    last = hops[-1] if hops else None
    if i == 1:
        return {
            "warum": "Zuerst billige Fakten: Magic, DIE/Packer, Strings – sonst decompiliert man den Packer-Stub.",
            "fund": (last or {}).get("fund", "") if last and last.get("op") in ("classify", "gate") else (
                f"Format {(classification or {}).get('kind', '?')}, Packer-Hinweise: "
                f"{', '.join((classification or {}).get('packer_hints') or []) or 'keine'}."
            ),
            "next": ["Schritt 2 starten, sobald DIE/Triage klar ist"],
            "tool": "diec / file / strings",
        }
    if i == 2:
        return {
            "warum": (route.warum_de if route else "Passende Toolchain wählen und Soldaten laufen lassen."),
            "fund": next((r.fund for r in reversed(results) if r.name != "triage"), "Noch kein Soldaten-Fund."),
            "next": list((route.next_de[1:2] if route else ["Ergebnis prüfen"])),
            "tool": (route.primary_skill if route else "soldat"),
        }
    return {
        "warum": "Alles, was wir gefunden haben, gehört mit Adresse und Tool-Namen ins Dossier – sonst ist die nächste Session blind.",
        "fund": "Dossier/Ledger werden beim Merge geschrieben.",
        "next": ["Dossier öffnen", "Next-3 aus dem Ledger weiterverfolgen"],
        "tool": "re-result-dossier",
    }


def build_bypass(
    route: Any | None,
    classification: dict | None,
    gate_dynamic: str = "no",
    oversight: bool = False,
    finished: bool = False,
) -> dict[str, Any]:
    """Packer-/Schutz-Bypass als eigener Flow-Schritt (nicht nur Textliste)."""
    packed = bool(classification and classification.get("packed"))
    kind = (classification or {}).get("kind") or "?"
    hints = list((classification or {}).get("packer_hints") or [])
    if not packed:
        return {
            "id": "bypass",
            "label": "Kein Packer-Bypass nötig",
            "status": "done",  # pending|active|done|blocked|n/a
            "playbook": getattr(route, "playbook", None) or "none",
            "requires_oversight": False,
            "warum": "Keine Packer-/Stub-Signale – wir können direkt statisch (rz-bin/Ghidra) weiter.",
            "fund": f"{kind}: klartext-analysierbar (Entropie/Sektionen ohne Packer-Hinweis).",
            "next": ["Ghidra-Headless oder rz-bin vertiefen", "Funde mit Adresse ins Dossier"],
            "hints": [],
        }
    # gepackt
    if gate_dynamic == "yes-lab" and oversight:
        status = "active" if not finished else "pending"
        note = "Oversight bestätigt – Yellow startet Packer-Bypass/Entpacken im Lab-Pfad selbst (dynamic-lab)."
    elif gate_dynamic != "no":
        status = "blocked"
        note = "Dynamic/Entpacken angefragt, aber Oversight fehlt → Bypass/Lab bleibt blockiert."
    else:
        status = "pending"
        note = "Statischer Unpacker-Stub lesen oder Lab-Entpacken mit Oversight planen."
    return {
        "id": "bypass",
        "label": "Packer-Bypass / Entpacken",
        "status": status,
        "playbook": "packer-unpack-re",
        "requires_oversight": True,
        "warum": "Gepackter Code: Ghidra auf dem Stub lohnt nicht. Erst Bypass/Unpack, dann pe-exe-re erneut.",
        "fund": f"Hinweise: {', '.join(hints) or 'hohe Entropie / Packer-Sektion'}. {note}",
        "next": [
            "DIE-Ausgabe prüfen (triage_diec.txt)",
            "Entpacken nur in Lab-VM mit Oversight",
            "Danach Route pe-exe-re + Ghidra-Headless",
        ],
        "hints": hints,
    }


def extract_findings(
    case_id: str,
    classification: dict | None,
    results: list[Any],
    ran_at: str | None = None,
) -> list[dict[str, Any]]:
    """Strukturierte Funde (Tool + Adresse + Snippet + Evidence-Link) für Ergebnisse-Panel."""
    out: list[dict[str, Any]] = []
    ts = ran_at or config.now_iso()
    c = classification or {}
    details = c.get("details") or {}

    def add(tool: str, soldier: str, title: str, snippet: str, address: str = "", evidence: str = "") -> None:
        out.append({
            "tool": tool,
            "soldier": soldier,
            "title": title,
            "address": address or "–",
            "snippet": (snippet or "")[:240],
            "evidence_path": evidence,
            "evidence_url": f"/yellow/case/{case_id}/evidence/{evidence}" if evidence else "",
            "dossier_url": f"/yellow/case/{case_id}/dossier.md",
            "ran_at": ts,
        })

    if c.get("sha256"):
        add("classify", "queen", "SHA-256 / Format",
            f"{c.get('kind')} · {c.get('subtype') or 'unbekannt'} · Entropie {c.get('entropy')}",
            address="file:0", evidence="")

    entry = details.get("entry_rva") or details.get("entry") or c.get("arch") and details.get("entry_rva")
    if details.get("entry_rva") is not None:
        try:
            addr = hex(int(details["entry_rva"]))
        except (TypeError, ValueError):
            addr = str(details["entry_rva"])
        add("pe-parser" if c.get("kind") in ("PE", "DOTNET") else "elf-parser",
            "classify", "Entry-Point / Entry-RVA",
            f"Einstieg bei {addr} ({c.get('arch') or 'arch?'})",
            address=addr)

    for sec in (details.get("sections") or [])[:8]:
        name = sec.get("name") or "?"
        ent = sec.get("entropy")
        try:
            addr = hex(int(sec.get("virt_addr") or sec.get("vaddr") or sec.get("raw_offset") or 0))
        except (TypeError, ValueError):
            addr = str(sec.get("virt_addr") or "–")
        add("pe-parser", "classify", f"Sektion {name}",
            f"Entropie {ent}" + (" · Packer-verdächtig" if ent and float(ent) > 7.2 else ""),
            address=addr)

    for r in results:
        # DIE
        diec = r.facts.get("diec")
        if diec:
            add("diec", r.name, "DIE Packer/Compiler",
                "; ".join(diec) if isinstance(diec, list) else str(diec),
                address="–", evidence="triage_diec.txt" if "triage_diec.txt" in r.evidence else "")
        # Imports head (rz-bin)
        for line in (r.facts.get("imports_head") or [])[:6]:
            # oft: "0x00401000  KERNEL32.dll  CreateFileA" o.ä.
            addr = "–"
            parts = str(line).split()
            if parts and parts[0].startswith("0x"):
                addr = parts[0]
            add("rz-bin", r.name, "Import", str(line)[:200], address=addr,
                evidence="pe_rzbin_imports.txt" if "pe_rzbin_imports.txt" in r.evidence else (
                    "elf_rzbin_imports.txt" if any("import" in e for e in r.evidence) else (r.evidence[0] if r.evidence else "")))
        # URLs/IPs aus Triage (ohne Secrets – schon redacted)
        for u in (r.facts.get("urls") or [])[:5]:
            add("strings", r.name, "URL in Strings", str(u), address="strings", evidence="triage_strings.txt")
        for ip in (r.facts.get("ips") or [])[:5]:
            add("strings", r.name, "IP-artig in Strings", str(ip), address="strings", evidence="triage_strings.txt")
        # rzbin info head
        for line in (r.facts.get("rzbin_info") or [])[:4]:
            add("rz-bin", r.name, "rz-bin -I", str(line)[:200], address="–",
                evidence=next((e for e in r.evidence if "info" in e), r.evidence[0] if r.evidence else ""))
        # Dynamic Lab findings
        if r.name == "dynamic":
            for line in (r.facts.get("strace_head") or r.facts.get("findings_head") or [])[:10]:
                addr = "–"
                sline = str(line)
                # strace oft: "12:00:01 execve(...)" oder "[pid] openat(AT_FDCWD, ..."
                add("strace" if "strace" in (r.tools_used or []) else "dynamic-lab", r.name,
                    "Dynamic Syscall/Event", sline[:200], address=addr,
                    evidence="dynamic_strace.txt" if "dynamic_strace.txt" in r.evidence else (
                        r.evidence[0] if r.evidence else ""))
            for line in (r.facts.get("frida_ps_head") or [])[:5]:
                add("frida", r.name, "Frida Prozess", str(line)[:200], address="lab",
                    evidence="dynamic_frida_ps.txt")
            if r.facts.get("frida_version"):
                add("frida", r.name, "Frida Lab", f"Version {r.facts['frida_version']}", address="lab",
                    evidence="dynamic_frida.txt" if "dynamic_frida.txt" in r.evidence else "")
            for line in (r.facts.get("gdb_head") or [])[:4]:
                add("gdb", r.name, "gdb info", str(line)[:200], address="–",
                    evidence="dynamic_gdb_info.txt")
        # entry from pe facts
        if r.facts.get("entry_rva") is not None and details.get("entry_rva") is None:
            try:
                addr = hex(int(r.facts["entry_rva"]))
            except (TypeError, ValueError):
                addr = str(r.facts["entry_rva"])
            add("rz-bin", r.name, "Entry-RVA (Soldat)", f"Entry {addr}", address=addr)

    # Dedup by (tool, title, address, snippet[:60])
    seen: set[tuple] = set()
    uniq: list[dict[str, Any]] = []
    for f in out:
        key = (f["tool"], f["title"], f["address"], f["snippet"][:60])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return uniq[:40]


def build_dynamic(
    gate_dynamic: str,
    oversight: bool,
    results: list[Any],
    finished: bool = False,
) -> dict[str, Any]:
    """Dynamic-Lab als eigener Flow-Schritt mit Status (pending/active/done/blocked)."""
    dyn_res = next((r for r in results if getattr(r, "name", "") == "dynamic"), None)
    if gate_dynamic == "no":
        return {
            "id": "dynamic",
            "label": "Kein Dynamic-Lab (nur statisch)",
            "status": "done",
            "playbook": "none",
            "requires_oversight": False,
            "warum": "Dynamic war nicht angefragt – rein statische Analyse.",
            "fund": "Kein Lab-Lauf.",
            "next": ["Bei Bedarf Analyse mit Dynamic+Oversight neu starten"],
            "tools_used": [],
        }
    if gate_dynamic == "ask" or (gate_dynamic != "yes-lab" and not oversight):
        return {
            "id": "dynamic",
            "label": "Dynamic-Lab BLOCKIERT (kein Oversight)",
            "status": "blocked",
            "playbook": "dynamic-lab",
            "requires_oversight": True,
            "warum": "Ohne Oversight starte ich keinen Lab-Lauf – Gate bleibt zu.",
            "fund": "Status ask/blocked. Setze Oversight und starte erneut für yes-lab.",
            "next": ["Oversight-Checkbox setzen", "Analyse erneut starten"],
            "tools_used": [],
        }
    # yes-lab
    if dyn_res is None and not finished:
        status = "active"
        fund = "Lab-Pfad startet gleich (strace/Frida/gdb)."
        tools: list[str] = []
    elif dyn_res is None:
        status = "pending"
        fund = "yes-lab freigeschaltet, aber noch kein Dynamic-Hop."
        tools = []
    else:
        st = getattr(dyn_res, "status", "ok")
        status = "done" if st in ("ok", "partial") else ("blocked" if st == "blocked" else st)
        if status == "partial":
            status = "done"  # gelaufen, ggf. unvollständig – UI: done mit Hinweis
        fund = getattr(dyn_res, "fund", "") or getattr(dyn_res, "summary_de", "")
        tools = list(getattr(dyn_res, "tools_used", []) or [])
    return {
        "id": "dynamic",
        "label": "Dynamic-Lab (Yellow führt aus)",
        "status": status,
        "playbook": "dynamic-lab / frida-lab",
        "requires_oversight": True,
        "warum": "Mit Oversight startet Yellow den Lab-Pfad selbst – kein bloßes Vormerken.",
        "fund": fund,
        "next": list(getattr(dyn_res, "next", None) or ["Evidence dynamic_* lesen", "Funde ins Dossier"]),
        "tools_used": tools,
    }


def next3_labels(steps: list[dict[str, Any]]) -> list[str]:

    """Rückwärtskompatibel: Liste von Label-Strings (Smoke len==3)."""
    return [s["label"] for s in steps[:3]]
