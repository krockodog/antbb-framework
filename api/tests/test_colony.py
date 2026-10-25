"""Kolonie-Verträge: drei Königinnen, getrennte Räume, Tore zu."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.catalog import DESCRIPTION, FOOTER, PRODUCT
from api.store import ColonyError, Settings, assert_runnable
from api.main import create_app

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def client(tmp_path: Path):
    settings = Settings(
        db_path=tmp_path / "colony.sqlite",
        data_dir=tmp_path / "runs",
        run_limit=3,
        classify_limit=4,
    )
    application = create_app(settings)
    with TestClient(application) as test_client:
        yield test_client


def _arm(client: TestClient, queen: str, target: str) -> None:
    scope = client.put(f"/api/queens/{queen}/scope", json={"allow": [target]})
    assert scope.status_code == 200
    oversight = client.post(f"/api/queens/{queen}/oversight", json={"armed": True})
    assert oversight.status_code == 200


def test_health_lists_three_queens(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["service"] == "all-and-one"
    assert body["queen_ids"] == ["red", "blue", "yellow"]


def test_health_per_queen(client: TestClient) -> None:
    for queen in ("red", "blue", "yellow"):
        response = client.get(f"/api/health/{queen}")
        assert response.status_code == 200
        assert response.json()["queen_id"] == queen


def test_health_rejects_unknown_queen(client: TestClient) -> None:
    response = client.get("/api/health/green")
    assert response.status_code == 422


def test_meta_brand_and_vocabulary(client: TestClient) -> None:
    body = client.get("/api/meta").json()
    assert body["product"] == PRODUCT
    assert body["description"] == DESCRIPTION
    assert body["footer"] == FOOTER
    assert "Monster" not in json.dumps(body)
    for noun in (
        "Königin",
        "Soldaten",
        "Playbooks",
        "Oversight",
        "Scope",
        "Dossier",
        "Ledger",
        "Live-Status",
    ):
        assert noun in body["nouns"]
    assert body["surface"] == {
        "host": "192.168.2.7",
        "port": 1001,
        "process": "one",
        "origin": "http://192.168.2.7:1001",
    }
    assert body["service"] == {
        "unit": "antbb.service",
        "working_directory": "/home/lordix/antbb",
    }
    assert body["roles"]["red"] == "Red-Teaming"
    assert body["roles"]["blue"] == "Blue Safety-Teaming"
    assert body["roles"]["yellow"] == "Yellow Reverse-Teaming"
    assert body["ports_documented"] == {"surface": 1001}
    raw = json.dumps(body)
    assert "1020" not in raw
    assert "1016" not in raw


def test_legal_notice_does_not_replace_oversight(client: TestClient) -> None:
    body = client.get("/api/legal").json()
    assert "202a" in body["notice"]
    assert "202c" in body["notice"]
    assert "CFAA" in body["notice"]
    assert body["replaces_oversight"] is False
    assert "ersetzt kein Oversight" in body["notice"]


def test_queens_are_namespaced(client: TestClient) -> None:
    listing = client.get("/api/queens")
    assert listing.status_code == 200
    rows = listing.json()
    assert [row["queen_id"] for row in rows] == ["red", "blue", "yellow"]
    red = client.get("/api/queens/red").json()
    blue = client.get("/api/queens/blue").json()
    yellow = client.get("/api/queens/yellow").json()
    assert red["queen_id"] == "red"
    assert blue["queen_id"] == "blue"
    assert yellow["queen_id"] == "yellow"
    assert set(red["soldier_ids"]).isdisjoint(blue["soldier_ids"])
    assert "greenbone-import" in blue["playbook_ids"]
    assert "greenbone-import" not in red["playbook_ids"]
    assert "recon-uebersicht" not in yellow["playbook_ids"]
    assert "format-klassifikation" in yellow["playbook_ids"]


def test_soldiers_carry_queen_id_and_stub(client: TestClient) -> None:
    from api.real_queens import real_soldier_ids

    cases = [("red", "mira"), ("blue", "henrik"), ("yellow", "ruza")]
    for queen, seed_id in cases:
        real = real_soldier_ids(queen)
        soldier_id = real[0] if real else seed_id
        body = client.get(f"/api/queens/{queen}/soldiers/{soldier_id}").json()
        assert body["queen_id"] == queen
        assert body["soldier_id"] == soldier_id
        if real:
            # Echte Registry-Soldaten: kein Mock-Stub mehr.
            assert body["stub"] is False
        else:
            assert body["stub"] is True
            assert "geplant/Mock" in body["stub_note"]
        for playbook in body["playbooks"]:
            assert playbook["queen_id"] == queen
            assert playbook["destructive"] is False


def test_cross_queen_soldier_is_hidden(client: TestClient) -> None:
    response = client.get("/api/queens/blue/soldiers/mira")
    assert response.status_code == 404
    assert "Königin" in response.json()["detail"]


def test_playbook_catalogs(client: TestClient) -> None:
    red = {item["playbook_id"] for item in client.get("/api/queens/red/playbooks").json()["playbooks"]}
    blue = {item["playbook_id"] for item in client.get("/api/queens/blue/playbooks").json()["playbooks"]}
    yellow = {
        item["playbook_id"] for item in client.get("/api/queens/yellow/playbooks").json()["playbooks"]
    }
    assert {"recon-uebersicht", "auth-lage", "fuzz-notiz", "verify-befund"} <= red
    assert {"patchmgmt", "tlsposture", "greenbone-import"} <= blue
    assert {"format-klassifikation", "erklaerpfad", "probenkarte"} <= yellow
    assert red.isdisjoint(blue)
    assert blue.isdisjoint(yellow)


def test_scope_defaults_to_deny(client: TestClient) -> None:
    body = client.get("/api/queens/red/scope").json()
    assert body == {"queen_id": "red", "mode": "default-deny", "allow": []}


def test_scope_rejects_wildcard(client: TestClient) -> None:
    response = client.put("/api/queens/red/scope", json={"allow": ["*"]})
    assert response.status_code == 400
    assert client.get("/api/queens/red/scope").json()["allow"] == []


def test_run_requires_oversight_and_scope(client: TestClient) -> None:
    bare = client.post(
        "/api/queens/red/runs",
        json={
            "soldier_id": "mira",
            "playbook_id": "recon-uebersicht",
            "oversight": True,
            "targets": ["labor-rot.intern"],
        },
    )
    assert bare.status_code == 403
    client.put("/api/queens/red/scope", json={"allow": ["labor-rot.intern"]})
    missing_flag = client.post(
        "/api/queens/red/runs",
        json={
            "soldier_id": "mira",
            "playbook_id": "recon-uebersicht",
            "oversight": False,
            "targets": ["labor-rot.intern"],
        },
    )
    assert missing_flag.status_code == 403
    client.post("/api/queens/red/oversight", json={"armed": True})
    outside = client.post(
        "/api/queens/red/runs",
        json={
            "soldier_id": "mira",
            "playbook_id": "recon-uebersicht",
            "oversight": True,
            "targets": ["woanders.example"],
        },
    )
    assert outside.status_code == 403
    assert "Allowlist" in outside.json()["detail"]


def test_successful_run_writes_dossier_and_ledger(client: TestClient, tmp_path: Path) -> None:
    _arm(client, "red", "labor-rot.intern")
    response = client.post(
        "/api/queens/red/runs",
        json={
            "soldier_id": "mira",
            "playbook_id": "recon-uebersicht",
            "oversight": True,
            "targets": ["labor-rot.intern"],
        },
    )
    assert response.status_code == 200
    dossier = response.json()
    assert dossier["queen_id"] == "red"
    assert dossier["soldier_id"] == "mira"
    assert dossier["playbook_id"] == "recon-uebersicht"
    assert dossier["stub"] is False          # echter Executor, kein Dossier-Mock
    assert dossier["evidence"]["executor"] in ("red-recon", "error")
    folder = tmp_path / "runs" / "red" / dossier["run_id"]
    assert (folder / "dossier.json").is_file()
    assert (folder / "ledger.jsonl").is_file()
    on_disk = json.loads((folder / "dossier.json").read_text(encoding="utf-8"))
    assert on_disk["queen_id"] == "red"
    ledger = (folder / "ledger.jsonl").read_text(encoding="utf-8").strip()
    assert json.loads(ledger)["queen_id"] == "red"
    assert not (tmp_path / "runs" / "blue" / dossier["run_id"]).exists()
    listed = client.get("/api/queens/red/ledger").json()
    assert listed["queen_id"] == "red"
    assert listed["ledger"][0]["run_id"] == dossier["run_id"]


def test_findings_do_not_cross_queens(client: TestClient) -> None:
    _arm(client, "red", "labor-rot.intern")
    created = client.post(
        "/api/queens/red/runs",
        json={
            "soldier_id": "karim",
            "playbook_id": "verify-befund",
            "oversight": True,
            "targets": ["labor-rot.intern"],
        },
    ).json()
    blue_runs = client.get("/api/queens/blue/runs").json()
    assert blue_runs["queen_id"] == "blue"
    assert blue_runs["runs"] == []
    hidden = client.get(f"/api/queens/blue/runs/{created['run_id']}")
    assert hidden.status_code == 404
    own = client.get(f"/api/queens/red/runs/{created['run_id']}")
    assert own.status_code == 200
    assert own.json()["queen_id"] == "red"


def test_cross_playbook_rejected(client: TestClient) -> None:
    _arm(client, "red", "labor-rot.intern")
    response = client.post(
        "/api/queens/red/runs",
        json={
            "soldier_id": "mira",
            "playbook_id": "greenbone-import",
            "oversight": True,
            "targets": ["labor-rot.intern"],
        },
    )
    assert response.status_code == 404


def test_forbidden_playbook_names_stay_shut(client: TestClient) -> None:
    _arm(client, "red", "labor-rot.intern")
    response = client.post(
        "/api/queens/red/runs",
        json={
            "soldier_id": "mira",
            "playbook_id": "brute-force",
            "oversight": True,
            "targets": ["labor-rot.intern"],
        },
    )
    assert response.status_code == 403


def test_destructive_gate() -> None:
    with pytest.raises(ColonyError) as caught:
        assert_runnable({"destructive": True})
    assert caught.value.status == 403


def test_rate_limit(client: TestClient) -> None:
    _arm(client, "blue", "labor-blau.intern")
    payload = {
        "soldier_id": "sina",
        "playbook_id": "patchmgmt",
        "oversight": True,
        "targets": ["labor-blau.intern"],
    }
    for _ in range(3):
        assert client.post("/api/queens/blue/runs", json=payload).status_code == 200
    blocked = client.post("/api/queens/blue/runs", json=payload)
    assert blocked.status_code == 429


def test_greenbone_stub_has_no_scanner(client: TestClient) -> None:
    book = client.get("/api/queens/blue/playbooks/greenbone-import").json()
    assert book["queen_id"] == "blue"
    assert book["stub"] is True
    assert "OpenVAS" in book["stub_note"] or "OpenVAS" in book["summary"]
    _arm(client, "blue", "labor-blau.intern")
    dossier = client.post(
        "/api/queens/blue/runs",
        json={
            "soldier_id": "henrik",
            "playbook_id": "greenbone-import",
            "oversight": True,
            "targets": ["labor-blau.intern"],
        },
    ).json()
    assert dossier["queen_id"] == "blue"
    # Echter GVM-Executor (kein Mock). Ohne gvm-cli/gvmd: ehrliche Fehlermeldung.
    assert dossier["stub"] is False
    assert dossier["evidence"]["executor"] == "blue-gvm"


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("probe.exe", "pe"),
        ("mscorlib-helper.dll", "dotnet"),
        ("app-release.apk", "apk"),
        ("libdemo.so", "elf"),
        ("firmware.hex", "hex"),
        ("tool.com", "dos"),
    ],
)
def test_yellow_classifies_formats(client: TestClient, name: str, kind: str) -> None:
    client.post("/api/queens/yellow/oversight", json={"armed": True})
    body = client.post(
        "/api/queens/yellow/classify",
        json={"name": name, "oversight": True},
    ).json()
    assert body["queen_id"] == "yellow"
    assert body["kind"] == kind
    assert body["withheld"] is False
    assert len(body["steps"]) >= 2
    for step in body["steps"]:
        assert step["erklaerbaerin"]
        assert "warum" in step["erklaerbaerin"].lower() or "Ich " in step["erklaerbaerin"]


def test_yellow_withholds_dynamic_steps_without_oversight(client: TestClient) -> None:
    closed = client.post(
        "/api/queens/yellow/classify",
        json={"name": "probe.exe", "oversight": False},
    ).json()
    assert closed["queen_id"] == "yellow"
    assert closed["kind"] == "pe"
    assert closed["withheld"] is True
    assert closed["withheld_count"] >= 1
    assert all(step["dynamic"] is False for step in closed["steps"])
    assert len(closed["steps"]) == 1
    client.post("/api/queens/yellow/oversight", json={"armed": True})
    still_closed = client.post(
        "/api/queens/yellow/classify",
        json={"name": "probe.exe", "oversight": False},
    ).json()
    assert still_closed["withheld"] is True
    opened = client.post(
        "/api/queens/yellow/classify",
        json={"name": "probe.exe", "oversight": True},
    ).json()
    assert opened["withheld"] is False
    assert any(step["dynamic"] for step in opened["steps"])


def test_yellow_run_embeds_plan(client: TestClient, tmp_path: Path) -> None:
    _arm(client, "yellow", "probe.exe")
    dossier = client.post(
        "/api/queens/yellow/runs",
        json={
            "soldier_id": "tilda",
            "playbook_id": "format-klassifikation",
            "oversight": True,
            "targets": ["probe.exe"],
            "probe_name": "probe.exe",
        },
    ).json()
    assert dossier["queen_id"] == "yellow"
    assert dossier["plan"]["kind"] == "pe"
    assert dossier["plan"]["steps"]
    folder = tmp_path / "runs" / "yellow" / dossier["run_id"]
    assert (folder / "dossier.json").is_file()
    assert not (tmp_path / "runs" / "red" / dossier["run_id"]).exists()


def test_brain_strip_and_footer(client: TestClient) -> None:
    body = client.get("/api/brain").json()
    assert body["product"] == PRODUCT
    assert body["footer"] == "All and One · Red · Blue · Yellow"
    assert body["strip"].startswith("Rot tut ")
    assert "Blau tut " in body["strip"]
    assert "Gelb tut " in body["strip"]
    assert "Monster" not in json.dumps(body)
    assert [queen["queen_id"] for queen in body["queens"]] == ["red", "blue", "yellow"]
    focused = client.get("/api/brain?queen=yellow").json()
    assert focused["focus"] == "yellow"
    assert client.get("/api/brain?queen=violet").status_code == 422


def test_declared_kind_overrides_name(client: TestClient) -> None:
    client.post("/api/queens/yellow/oversight", json={"armed": True})
    body = client.post(
        "/api/queens/yellow/classify",
        json={"name": "probe.exe", "declared_kind": "elf", "oversight": True},
    ).json()
    assert body["kind"] == "elf"
    assert body["queen_id"] == "yellow"


def test_one_process_serves_surface(client: TestClient) -> None:
    index = ROOT / "all-and-one" / "out" / "index.html"
    if not index.is_file():
        pytest.skip("Oberfläche nicht gebaut")
    for path in (
        "/",
        "/red",
        "/blue",
        "/yellow",
        "/yellow/laeufe",
        "/brain",
        "/red/brain",
        "/blue/brain",
        "/yellow/brain",
    ):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "text/html" in response.headers["content-type"]
        assert "All and One" in response.text
    assert client.get("/red.txt").status_code == 200
    assert client.get("/api/health").json()["service"] == "all-and-one"
    assert client.get("/api/does-not-exist").status_code == 404
    assert client.get("/does-not-exist").status_code == 404
    chunk = next((ROOT / "all-and-one" / "out" / "_next").rglob("*.js"))
    rel = "/" + chunk.relative_to(ROOT / "all-and-one" / "out").as_posix()
    asset = client.get(rel)
    assert asset.status_code == 200
    assert "javascript" in asset.headers["content-type"]


def test_docs_use_official_name() -> None:
    for relative in ("README.md", "DEMO.md", "DEPLOY.md", "docs/wortschatz.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert PRODUCT in text
        assert "Monster" not in text
        assert "Ameisen-Schwarm" not in text
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert DESCRIPTION in readme
    deploy = (ROOT / "DEPLOY.md").read_text(encoding="utf-8")
    assert "http://192.168.2.7:1001" in deploy
    assert "/home/lordix/antbb" in deploy
    assert "antbb.service" in deploy
    assert "cap_net_bind_service" in deploy
    assert "Red-Teaming" in deploy
    assert "Yellow Reverse-Teaming" in deploy
    assert "Blue Safety-Teaming" in deploy
    assert "1020" not in deploy
    for relative in ("README.md", "DEMO.md", "run.sh", "api/main.py", "api/catalog.py"):
        assert "1020" not in (ROOT / relative).read_text(encoding="utf-8")
    unit = (ROOT / "deploy" / "antbb.service").read_text(encoding="utf-8")
    assert "WorkingDirectory=/home/lordix/antbb" in unit
    assert "ALLONE_PORT=1001" in unit
    assert "--port 1001" in unit
    assert "1020" not in unit
    assert "1016" not in unit
    hub = (ROOT / "all-and-one" / "src" / "app" / "page.tsx").read_text(encoding="utf-8")
    assert PRODUCT in hub
    assert DESCRIPTION in hub
    brain = (ROOT / "all-and-one" / "src" / "components" / "neural-brain.tsx").read_text(
        encoding="utf-8"
    )
    assert FOOTER in brain
    assert "Monster" not in brain
