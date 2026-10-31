"""Smoke-Tests der Gelben Königin (Reverse-Engineering-Kolonie).

antbb.agents.yellow wurde in Commit 8397411 entfernt. Die Datei wird
übersprungen, statt Yellow-Soldaten neu zu erfinden.
"""
import pytest

pytest.skip(
    "antbb.agents.yellow wurde in 8397411 entfernt; Yellow-Soldaten werden nicht neu erfunden.",
    allow_module_level=True,
)

import hashlib
import os
import tempfile

from antbb.agents.yellow import YELLOW_AGENTS, YELLOW_PHASES
from antbb.registry import build_registry
from antbb.store import Store
from antbb.yellow_queen import YellowQueen


def test_yellow_roster_discovered():
    names = {c.name for c in YELLOW_AGENTS}
    assert {"yellow-doctor", "yellow-intake", "yellow-strings", "yellow-dossier"} <= names
    assert len(YELLOW_AGENTS) >= 8
    for c in YELLOW_AGENTS:
        assert c.describe()["colony"] == "yellow"


def test_registry_includes_yellow():
    reg = build_registry()
    assert reg.get("yellow_soldier_count", 0) >= 8
    assert list(YELLOW_PHASES) == reg.get("yellow_phases")


def test_yellow_queen_runs_readonly():
    db = tempfile.mktemp(suffix=".sqlite")
    store = Store(db)
    sp = tempfile.mktemp()
    with open(sp, "wb") as fh:
        fh.write(b"\x7fELF" + b"A" * 128 + b"https://example.com AES")
    q = YellowQueen(store, use_llm=False)
    res = q.run_colony_sync(params={"sample": sp})
    assert res.run_id.startswith("yellow-")
    assert len(res.findings) >= 2
    cats = {f.category for f in res.findings}
    assert any(c.startswith("yellow-") for c in cats)
