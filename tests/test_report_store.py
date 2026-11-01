"""Report-Ablage je Königin: Pfadschutz, Yellow-Fall, Liste, Routen."""
import pytest

from antbb import report_store as rs


def test_safe_path_rejects_traversal(tmp_path):
    for bad in ["../x.pdf", "red-../../etc-20260101-000000.pdf", "blue-x-20260101-000000.pdf",
                "red-x.pdf", "red-x-20260101-000000.exe", "/etc/passwd"]:
        with pytest.raises(rs.ReportError):
            rs.safe_path("red", bad, root=tmp_path)
    with pytest.raises(rs.ReportError):
        rs.queen_dir("green", root=tmp_path)
    ok = rs.safe_path("red", "red-target1-20260101-000000.pdf", root=tmp_path)
    assert ok.parent == (tmp_path / "red").resolve()


def test_yellow_case_report(tmp_path):
    cases = tmp_path / "cases"
    (cases / "yq-test-1").mkdir(parents=True)
    (cases / "yq-test-1" / "dossier.md").write_text("# Dossier\nTestinhalt <b>", encoding="utf-8")
    res = rs.generate_yellow("yq-test-1", root=tmp_path / "rep", cases_dir=cases)
    assert res["ok"] and res["html"].startswith("/reports/yellow/yellow-yq-test-1-")
    listed = rs.list_reports(root=tmp_path / "rep")
    kinds = {r["kind"] for r in listed["yellow"]}
    assert "html" in kinds
    if res["engine"]:
        assert "pdf" in kinds
    with pytest.raises(rs.ReportError):
        rs.generate_yellow("../etc", root=tmp_path / "rep", cases_dir=cases)
    with pytest.raises(rs.ReportError):
        rs.generate_yellow("fehlt", root=tmp_path / "rep", cases_dir=cases)


def test_routes(tmp_path, monkeypatch):
    monkeypatch.setattr(rs, "REPORTS_ROOT", tmp_path)
    from fastapi.testclient import TestClient
    from antbb.web.app import app
    c = TestClient(app)
    assert c.get("/api/reports").status_code == 200
    assert c.get("/reports").status_code == 200
    assert c.get("/reports/red/..%2F..%2Fetc%2Fpasswd").status_code in (400, 404)
    assert c.get("/reports/red/red-x-20260101-000000.pdf").status_code == 404
    r = c.post("/api/reports/generate", json={"queen": "green"})
    assert r.status_code == 400
    r = c.post("/api/reports/generate", json={"queen": "red", "target_id": 987654})
    assert r.status_code == 400
