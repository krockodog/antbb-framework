"""Gates: Autorisierung Pflicht, Dynamic nur mit Oversight (dann Lab-Lauf durch Yellow)."""
from __future__ import annotations

from dataclasses import dataclass


class GateError(Exception):
    """Ein Gate blockiert den Lauf (HTTP 403)."""


@dataclass
class GateResult:
    authorized: bool
    dynamic_requested: bool
    oversight: bool
    dynamic: str  # no | ask | yes-lab
    notes_de: list[str]


GATE_TEXT_DE = (
    "Nur autorisierte Ziele: eigene Binaries, freigegebene Samples, aufgegebene Spiele/Research oder Malware-Lab. "
    "Kein Crack/DRM/Lizenz-Bypass. Secrets werden nie gespeichert (Schwärzung). "
    "Dynamic/Ausführung: Yellow startet den Lab-Pfad (Playbook dynamic-lab / frida-lab) selbst – "
    "aber nur mit Oversight-Bestätigung. Ohne Oversight bleibt Dynamic blockiert (ask)."
)


def truthy(v: object) -> bool:
    return str(v).strip().lower() in {"1", "true", "on", "yes", "ja", "y"}


def check(authorized: object, dynamic: object = False, oversight: object = False) -> GateResult:
    if not truthy(authorized):
        raise GateError(
            "Gate Autorisierung: Ohne bestätigte Autorisierung wird nichts gespeichert. "
            "Bitte bestätige, dass das Sample dir gehört bzw. freigegeben ist (eigen/Lab/Research)."
        )
    dyn, ovs = truthy(dynamic), truthy(oversight)
    notes = []
    if dyn and not ovs:
        mode = "ask"
        notes.append("Dynamic angefragt, aber Oversight fehlt → Status 'ask'/blocked; es wird nichts im Lab ausgeführt.")
    elif dyn and ovs:
        mode = "yes-lab"
        notes.append(
            "Dynamic mit Oversight freigeschaltet → Yellow startet den Lab-Pfad selbst "
            "(Playbook dynamic-lab / frida-lab: strace/Frida/gdb, kurz, geloggt)."
        )
    else:
        mode = "no"
        notes.append("Nur statische Analyse – kein Dynamic-Lab-Lauf.")
    return GateResult(True, dyn, ovs, mode, notes)
