"""Blue-AV, Quarantäne und echte Protect-Aktionen.

Subprocess wird nur gemockt, um die Parse-/Apply-Logik zu isolieren.
Der Integrationspfad ohne Mock meldet fehlendes ClamAV ehrlich und erfindet
keine Virenfunde.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import socket

import pytest

from antbb import avscan, hardening_apply, honeypot, quarantine, watcher
from antbb.agents.base import AgentContext, Task
from antbb.agents.blue import BLUE_AGENTS
from antbb.agents.blue.honeypot import HoneypotAnt
from antbb.agents.blue.incident import IncidentAnt
from antbb.hardening import CheckResult
from antbb.registry import build_registry


def _ctx(active: bool, scope):
    return AgentContext(
        run_id="t-blue", scope_check=scope, logger=logging.getLogger("t-blue"),
        active=active,
    )


def test_soldier_registered():
    assert "blue-av" in {a.name for a in BLUE_AGENTS}
    soldier = next(s for s in build_registry()["soldiers"] if s["name"] == "blue-av")
    assert soldier["skill"]["has_skill_md"]
    names = {p["name"] for p in soldier["playbooks"]}
    assert {"av-scan", "av-quarantine"} <= names
    root = os.path.join(os.path.dirname(__file__), "..", "antbb", "playbooks", "blue")
    assert os.path.isfile(os.path.join(root, "pb-av-scan.md"))
    assert os.path.isfile(os.path.join(root, "pb-av-quarantine.md"))


def test_parse_found_and_ok_ignores_summary():
    text = "\n".join([
        "/tmp/a.txt: OK",
        "/tmp/b.bin: Win.Test.EICAR FOUND",
        "----------- SCAN SUMMARY -----------",
        "Infected files: 1",
        "/tmp/c.txt: OK",
    ])
    rows = avscan.parse_clam_output(text, "", 1)
    assert [r["verdict"] for r in rows] == ["clean", "infected"]
    assert rows[1]["signature"] == "Win.Test.EICAR"
    assert rows[1]["path"] == "/tmp/b.bin"


def test_parse_summary_only_has_no_findings():
    rows = avscan.parse_clam_output(
        "----------- SCAN SUMMARY -----------\nInfected files: 0\n", "", 0)
    assert rows == []


def test_scan_parses_runner_and_hashes_real_file(tmp_path):
    target = tmp_path / "sample.bin"
    data = b"sample-bytes-not-a-virus"
    target.write_bytes(data)

    def runner(cmd):
        path = cmd[-1]
        return avscan.CmdResult(1, f"{path}: Eicar-Test-Signature FOUND\n", "")

    report = avscan.scan_paths(
        [str(target)], scope_check=lambda p: True, runner=runner, engine="clamscan",
    )
    assert report.status == "completed"
    assert report.infected_count == 1
    assert report.clean is False
    hit = report.files[0]
    assert hit.path == str(target.resolve()) or hit.path == os.path.abspath(target)
    assert hit.sha256 == hashlib.sha256(data).hexdigest()
    assert hit.signature == "Eicar-Test-Signature"
    assert hit.verdict == "infected"


def test_scope_deny_does_not_invoke_scanner(tmp_path):
    target = tmp_path / "x.txt"
    target.write_text("FOUND inside the file must not become a finding\n")
    called = []

    def runner(cmd):
        called.append(cmd)
        return avscan.CmdResult(0, f"{cmd[-1]}: OK\n", "")

    report = avscan.scan_paths(
        [str(target)], scope_check=lambda p: False, runner=runner, engine="clamscan",
    )
    assert called == []
    assert report.status == "denied"
    assert report.clean is False
    assert report.infected_count == 0
    assert all(f.verdict != "infected" for f in report.files)


def test_missing_scope_and_empty_paths_are_not_clean(tmp_path):
    target = tmp_path / "x.txt"
    target.write_text("hello\n")
    denied = avscan.scan_paths([str(target)], scope_check=None)
    assert denied.status == "denied"
    assert denied.clean is False
    empty = avscan.scan_paths([], scope_check=lambda p: True)
    assert empty.status == "empty"
    assert empty.clean is False
    assert empty.infected_count == 0


def test_missing_engine_is_not_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(avscan, "which_engine", lambda: None)
    target = tmp_path / "note.txt"
    target.write_text("this text says FOUND but no scanner ran\n")
    report = avscan.scan_paths([str(target)], scope_check=lambda p: True)
    assert report.status == "unavailable"
    assert report.clean is False
    assert report.infected_count == 0
    assert report.files[0].verdict == "not_scanned"
    assert report.files[0].sha256 == hashlib.sha256(target.read_bytes()).hexdigest()
    assert report.files[0].signature == ""


def test_integration_honest_about_clamav(tmp_path):
    target = tmp_path / "clean.txt"
    target.write_text("hello antbb\n")
    report = avscan.scan_paths(
        [str(target)],
        scope_check=lambda p: os.path.abspath(str(p)).startswith(str(tmp_path)),
    )
    if avscan.which_engine() is None:
        assert report.status == "unavailable"
        assert report.clean is False
        assert report.infected_count == 0
        assert all(f.verdict != "infected" for f in report.files)
    else:
        assert report.status == "completed"
        assert report.files[0].sha256
        assert report.files[0].verdict == "clean"
        assert report.clean is True


def test_quarantine_requires_oversight_and_scope(tmp_path):
    src = tmp_path / "user.txt"
    src.write_text("keep-me")
    scope = lambda p: str(p).startswith(str(tmp_path))
    denied = quarantine.quarantine_move(str(src), active=False, scope_check=scope, root=str(tmp_path / "q"))
    assert denied.status == "denied"
    assert denied.applied is False
    assert src.read_text() == "keep-me"
    oos = quarantine.quarantine_move(str(src), active=True, scope_check=lambda p: False,
                                    root=str(tmp_path / "q"))
    assert oos.status == "denied"
    assert src.is_file()
    assert not (tmp_path / "q").exists() or not any((tmp_path / "q").glob("*.bin"))


def test_quarantine_move_is_reversible_and_recheck_closes(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    src = allowed / "payload.txt"
    data = b"payload-bytes"
    src.write_bytes(data)
    root = tmp_path / "quarantine"
    scope = lambda p: os.path.abspath(str(p)).startswith(str(allowed))

    moved = quarantine.quarantine_move(str(src), active=True, scope_check=scope, root=str(root))
    assert moved.applied is True
    assert moved.closed is True
    assert not src.exists()
    manifest = moved.evidence["manifest"]
    qpath = manifest["quarantine_path"]
    assert os.path.isfile(qpath)
    assert open(qpath, "rb").read() == data
    assert manifest["sha256"] == hashlib.sha256(data).hexdigest()
    recheck = moved.evidence["recheck"]
    assert recheck["closed"] is True
    assert recheck["before"]["sha256"] == manifest["sha256"]
    assert recheck["after"]["present"] is False
    assert recheck["after"]["hash_match"] is True

    restored = quarantine.restore_file(
        manifest["id"], active=True, scope_check=scope, root=str(root),
    )
    assert restored.applied is True
    assert src.read_bytes() == data
    assert not os.path.isfile(qpath)


def test_quarantine_refuses_system_path_and_symlink(tmp_path):
    scope = lambda p: True
    blocked = quarantine.quarantine_move(
        "/etc/passwd", active=True, scope_check=scope, root=str(tmp_path / "q"),
    )
    assert blocked.status == "denied"
    assert blocked.applied is False
    target = tmp_path / "real.txt"
    target.write_text("x")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    linked = quarantine.quarantine_move(str(link), active=True, scope_check=scope, root=str(tmp_path / "q"))
    assert linked.status == "denied"
    assert target.read_text() == "x"


def test_isolate_unavailable_without_ufw(monkeypatch):
    monkeypatch.setattr(quarantine, "ufw_present", lambda: False)
    result = quarantine.isolate_source(
        "203.0.113.9", active=True, scope_check=lambda p: True, ufw_installed=False,
    )
    assert result.status == "unavailable"
    assert result.applied is False
    assert result.closed is False
    assert result.evidence["intended_command"][-1] == "203.0.113.9"


def test_isolate_and_release_with_runner():
    ip = "203.0.113.9"
    calls = []

    def runner(cmd, input_text=None):
        calls.append(list(cmd))
        if list(cmd)[:2] == ["ufw", "status"]:
            if any(c[:4] == ["ufw", "insert", "1", "deny"] for c in calls):
                return f"Status: active\nAnywhere DENY {ip}\n"
            return "Status: active\n"
        return ""

    scope = lambda p: p == ip
    result = quarantine.isolate_source(
        ip, active=True, scope_check=scope, runner=runner, ufw_installed=True,
    )
    assert result.applied is True
    assert result.verified is True
    assert result.closed is True
    assert result.evidence["before"]
    assert ip in result.evidence["after"]
    assert any(c[:4] == ["ufw", "insert", "1", "deny"] and c[-1] == ip for c in calls)

    denied = quarantine.isolate_source(ip, active=False, scope_check=scope, runner=runner, ufw_installed=True)
    assert denied.status == "denied"
    oos = quarantine.isolate_source("203.0.113.8", active=True, scope_check=scope,
                                   runner=runner, ufw_installed=True)
    assert oos.status == "denied"

    def release_runner(cmd, input_text=None):
        if list(cmd)[:2] == ["ufw", "status"] and any(c[1] == "delete" for c in calls):
            return "Status: active\n"
        calls.append(list(cmd))
        if list(cmd)[:2] == ["ufw", "status"]:
            return f"Status: active\nAnywhere DENY {ip}\n"
        return ""

    calls.clear()
    released = quarantine.release_isolation(
        ip, active=True, scope_check=scope, runner=release_runner, ufw_installed=True,
    )
    assert released.applied is True
    assert any(c[:3] == ["ufw", "delete", "deny"] for c in calls)


def test_honeypot_deploy_is_real_and_gated(tmp_path):
    honeypot.stop_canary()
    denied = honeypot.deploy_canary(active=False, scope_check=lambda p: True, http_port=0, ssh_port=0)
    assert denied.status == "denied"
    assert denied.applied is False
    assert honeypot.canary_status()["running"] == []
    no_scope = honeypot.deploy_canary(active=True, scope_check=lambda p: False, http_port=0, ssh_port=0)
    assert no_scope.status == "denied"
    public = honeypot.deploy_canary(
        active=True, scope_check=lambda p: True, bind="0.0.0.0", http_port=0, ssh_port=0,
    )
    assert public.status == "failed"
    assert public.applied is False

    started = honeypot.deploy_canary(
        active=True, scope_check=lambda p: p in ("decoy", "localhost"),
        http_port=0, ssh_port=0, log_dir=str(tmp_path),
    )
    try:
        assert started.applied is True
        assert started.status in ("applied", "partial")
        assert started.evidence["cowrie"] == "not-started"
        http = next(item for item in started.listeners if item["kind"] == "http")
        with socket.create_connection(("127.0.0.1", http["port"]), timeout=2) as sock:
            sock.sendall(b"GET /canary HTTP/1.0\r\nHost: localhost\r\n\r\n")
            data = sock.recv(200)
        assert b"canary" in data
        lines = [a["line"] for a in honeypot.canary_status()["attempts"]]
        assert any("GET /canary" in line for line in lines)
    finally:
        honeypot.stop_canary()
        assert honeypot.canary_status()["running"] == []


def test_honeypot_agent_starts_canary_only_with_oversight(tmp_path):
    honeypot.stop_canary()
    scope = lambda p: p in ("decoy", "localhost", "127.0.0.1")
    quiet = HoneypotAnt(_ctx(False, scope))
    task = Task(phase="defend", target_id=0, target_name="localhost", assets=["decoy"], params={
        "canary_http_port": 0, "canary_ssh_port": 0, "canary_log_dir": str(tmp_path),
    })
    denied = asyncio.run(quiet.work(task))
    assert any(f.evidence.get("status") == "denied" for f in denied)
    assert honeypot.canary_status()["running"] == []

    live = HoneypotAnt(_ctx(True, scope))
    try:
        started = asyncio.run(live.work(task))
        deploy = next(f for f in started if f.category == "blue-honeypot-deploy")
        assert deploy.evidence["applied"] is True
        assert deploy.evidence["evidence"]["cowrie"] == "not-started" or deploy.evidence.get("cowrie") == "not-started"
    finally:
        honeypot.stop_canary()


def test_hardening_apply_is_gated_and_rechecks(monkeypatch):
    ssh = CheckResult(
        "ssh-password-auth", "SSH PasswordAuthentication", "fail",
        "PasswordAuthentication=yes", "PasswordAuthentication no", "medium",
    )
    calls = []

    def boom(command, input_text=None):
        raise AssertionError("runner ohne Freigabe")

    blocked = hardening_apply.apply_reversible(
        [ssh], active=False, scope_check=lambda p: p == "localhost", runner=boom,
    )
    assert blocked[0]["status"] == "denied"
    no_scope = hardening_apply.apply_reversible(
        [ssh], active=True, scope_check=lambda p: False, runner=boom,
    )
    assert no_scope[0]["status"] == "denied"

    def runner(command, input_text=None):
        calls.append((list(command), input_text))
        return "Status: active\n"

    class Step:
        closed = False
        evidence = {"before": "fail", "after": "fail", "recheck_status": "fail"}

    open_result = hardening_apply.apply_reversible(
        [ssh], active=True, scope_check=lambda p: p == "localhost",
        runner=runner, recheck=lambda finding: Step(),
    )
    assert open_result[0]["check_id"] == "ssh-password-auth"
    assert open_result[0]["applied"] is True
    assert open_result[0]["closed"] is False
    assert open_result[0]["evidence"]["before"] == "fail"
    blob = " ".join((text or "") for _cmd, text in calls)
    assert "PasswordAuthentication no" in blob

    class Closed:
        closed = True
        evidence = {"before": "fail", "after": "pass", "recheck_status": "pass"}

    calls.clear()
    closed = hardening_apply.apply_reversible(
        [ssh], active=True, scope_check=lambda p: p == "localhost",
        runner=runner, recheck=lambda finding: Closed(),
    )
    assert closed[0]["closed"] is True
    assert closed[0]["status"] == "GESCHLOSSEN"
    assert closed[0]["evidence"]["after"] == "pass"

    monkeypatch.setattr(hardening_apply, "_ufw_present", lambda: False)
    fw = CheckResult("host-firewall", "Host-Firewall", "fail", "ufw fehlt")
    missing = hardening_apply.apply_reversible(
        [fw], active=True, scope_check=lambda p: True, runner=runner,
    )
    assert missing[0]["status"] == "unavailable"
    assert missing[0]["applied"] is False

    monkeypatch.setattr(hardening_apply, "_ufw_present", lambda: True)
    monkeypatch.setattr(hardening_apply, "_risky_ports", lambda: [])
    skipped = hardening_apply.apply_reversible(
        [fw], active=True, scope_check=lambda p: True, runner=runner,
    )
    assert skipped[0]["status"] == "skipped"
    assert all("enable" not in " ".join(cmd) for cmd, _text in calls)

    monkeypatch.setattr(hardening_apply, "_risky_ports", lambda: [3306])

    def fw_runner(command, input_text=None):
        calls.append((list(command), input_text))
        if list(command)[:2] == ["ufw", "status"]:
            return "Status: active\n3306/tcp DENY Anywhere\n"
        return ""

    calls.clear()
    bound = hardening_apply.apply_reversible(
        [fw], active=True, scope_check=lambda p: True, runner=fw_runner,
    )
    assert bound[0]["applied"] is True
    assert bound[0]["closed"] is True
    assert 3306 in bound[0]["evidence"]["ports"]
    joined = " ".join(" ".join(cmd) for cmd, _text in calls)
    assert "3306" in joined
    assert "ufw enable" not in joined


def test_watcher_and_incident_apply_real_actions(tmp_path):
    honeypot.stop_canary()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    src = allowed / "drop.bin"
    data = b"drop-bytes"
    src.write_bytes(data)
    ip = "203.0.113.50"
    calls = []

    def runner(cmd, input_text=None):
        calls.append(list(cmd))
        if list(cmd)[:2] == ["ufw", "status"]:
            if any(c[:4] == ["ufw", "insert", "1", "deny"] for c in calls):
                return f"Status: active\nAnywhere DENY {ip}\n"
            return "Status: inactive\n"
        return ""

    def scope(asset):
        text = os.path.abspath(str(asset)) if str(asset).startswith("/") else str(asset)
        return text.startswith(str(allowed)) or text in ("decoy", "localhost", "127.0.0.1", ip)

    events = [{
        "source": ip, "file": str(src), "message": "failed password for root", "ts": 1.0,
    }]
    idle = watcher.run_watch(events, active=False, apply_protect=False, scope_check=scope)
    assert src.is_file()
    assert all(not p.get("applied") for p in idle.protects)

    try:
        report = watcher.run_watch(
            events, active=True, apply_protect=True, scope_check=scope,
            isolate_runner=runner, canary_http_port=0, canary_ssh_port=0,
            canary_log_dir=str(tmp_path),
        )
    finally:
        honeypot.stop_canary()
    assert report.summary["detection_count"] >= 1
    assert any(p.get("applied") and (p.get("evidence") or {}).get("isolate", {}).get("closed")
               for p in report.protects)
    quarantine_hit = next(p for p in report.protects if p.get("action") == "quarantine-move")
    assert quarantine_hit["evidence"]["closed"] is True
    assert not src.exists()
    assert quarantine_hit["evidence"]["recheck"]["after"]["sha256"] == hashlib.sha256(data).hexdigest()

    scope_agent = lambda p: os.path.abspath(str(p)).startswith(str(allowed)) if str(p).startswith("/") else False
    other = allowed / "other.txt"
    other.write_text("still-here")
    agent = IncidentAnt(_ctx(False, scope_agent))
    task = Task(
        phase="defend", target_id=0, target_name="localhost", assets=["localhost"],
        params={"apply_contain": True, "quarantine_paths": [str(other)],
                "quarantine_root": str(tmp_path / "q2")},
    )
    blocked = asyncio.run(agent.work(task))
    assert other.is_file()
    assert any(f.category == "blue-incident-action" and f.evidence.get("closed") is False for f in blocked)

    live = IncidentAnt(_ctx(True, lambda p: str(p).startswith(str(allowed)) or os.path.abspath(str(p)).startswith(str(allowed))))
    done = asyncio.run(live.work(task))
    closed = [f for f in done if f.status == "GESCHLOSSEN"]
    assert closed
    assert closed[0].evidence["before"]
    assert closed[0].evidence["after"]["hash_match"] is True
    assert not other.exists()
