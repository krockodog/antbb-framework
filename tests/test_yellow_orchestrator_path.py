"""Orchestrate steps must use the case folder, not data/cases."""
import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "yq_orchestrator_under_test",
    _ROOT / "yellow-queen" / "orchestrator.py",
)
orch = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(orch)


def test_resolve_prefers_cases_dir_evidence(tmp_path: Path):
    cases = tmp_path / "cases"
    data = tmp_path / "data"
    case_id = "yq-20260101-000000-abcdef12"
    evidence = cases / case_id / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "sample.bin").write_bytes(b"MZ" + b"\x00" * 64)

    # A stale legacy folder must not win once the canonical sample exists.
    legacy = data / "cases" / case_id
    legacy.mkdir(parents=True)
    (legacy / "decoy.exe").write_bytes(b"nope")

    resolved = orch.resolve_case_directory(case_id, cases_dir=cases, data_dir=data)
    assert resolved == cases / case_id
    assert orch._find_case_file(resolved) == evidence / "sample.bin"


def test_legacy_data_cases_is_only_a_fallback(tmp_path: Path):
    cases = tmp_path / "cases"
    data = tmp_path / "data"
    case_id = "yq-legacy-1"
    legacy = data / "cases" / case_id / "evidence"
    legacy.mkdir(parents=True)
    (legacy / "sample.bin").write_bytes(b"MZ" + b"\x00" * 32)

    resolved = orch.resolve_case_directory(case_id, cases_dir=cases, data_dir=data)
    assert resolved == data / "cases" / case_id
    assert (resolved / "evidence" / "sample.bin").is_file()


def test_run_step_reads_evidence_sample_and_still_requires_oversight(tmp_path: Path):
    case = tmp_path / "yq-sample"
    (case / "evidence").mkdir(parents=True)
    # Minimal MZ/PE is not required; triage records the bytes either way.
    (case / "evidence" / "sample.bin").write_bytes(b"MZ" + b"hello-sample" + b"\x00" * 80)

    blocked = orch.run_step(tmp_path, "yq-sample", "triage", oversight_ok=False, directory=case)
    assert blocked["ok"] is False
    assert "Oversight" in blocked["error"]

    done = orch.run_step(tmp_path, "yq-sample", "triage", oversight_ok=True, directory=case)
    assert done["ok"] is True
    assert (case / "triage_report.json").is_file()
    assert done["result"]["findings"]["file"] == "sample.bin"
    # The legacy path must not have been created beside the real case folder.
    assert not (tmp_path / "cases" / "yq-sample").exists()
