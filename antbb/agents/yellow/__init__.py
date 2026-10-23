"""Reverse-Engineering-Kolonie (Yellow Queen) – Yellow-Team-Soldaten.

Getrenntes Roster von den offensiven Arbeiter-Ameisen und von Blau. Dieselbe
Soldaten-Schnittstelle (AntAgent/AgentFinding/Playbook) + Registry/GUI-Karten.

Das Roster wird per AUTO-DISCOVERY aufgebaut: jedes Modul in diesem Paket, das
eine konkrete `YellowAgent`-Unterklasse mit eigenem `name` definiert, wird
registriert. Neue Soldaten brauchen nur eine neue Datei + SKILL.md.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil

from .base import YellowAgent, YELLOW_PHASES

_SKIP = {"base"}

#: Bevorzugte Reihenfolge (Erklärpfad intake → … → dossier).
_ORDER = [
    "yellow-doctor", "yellow-intake", "yellow-strings", "yellow-elf-macho",
    "yellow-pe-exe", "yellow-apk", "yellow-dotnet", "yellow-ghidra",
    "yellow-malware-triage", "yellow-dossier",
]


def _discover() -> list[type]:
    found: dict[str, type] = {}
    for mod in pkgutil.iter_modules(__path__):
        if mod.name in _SKIP:
            continue
        try:
            m = importlib.import_module(f"{__name__}.{mod.name}")
        except Exception:
            continue
        for _n, obj in inspect.getmembers(m, inspect.isclass):
            if (issubclass(obj, YellowAgent) and obj.__module__ == m.__name__
                    and obj.__name__ != "YellowAgent"
                    and not inspect.isabstract(obj)
                    and getattr(obj, "name", "ant") not in ("ant", "")):
                found[obj.name] = obj
    rank = {n: i for i, n in enumerate(_ORDER)}
    return [found[n] for n in sorted(found, key=lambda n: (rank.get(n, 999), n))]


#: Alle Yellow-Team-Soldaten der Reverse-Engineering-Königin (Reihenfolge = Erklärpfad).
YELLOW_AGENTS = _discover()

for _cls in YELLOW_AGENTS:
    globals()[_cls.__name__] = _cls

__all__ = ["YellowAgent", "YELLOW_PHASES", "YELLOW_AGENTS"] + [c.__name__ for c in YELLOW_AGENTS]
