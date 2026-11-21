"""Tests für den Safe-JSON-Parser (ABPM-12) und seine Anbindung.

Geprüft wird:
  * antbb.tools.parsers: ok / partial_fallback / empty, parse_warning immer
    gesetzt, wenn ein Fallback griff, und keine erfundenen Daten.
  * kali.py: parse_warning landet im Scan-Log, in ``parse_events`` und in der
    Evidence der daraus entstandenen Funde.
  * greenbone.parse_json: parse_status/parse_warning in meta, warnings, summary.

Für die Kali-Adapter wird nur der Subprozess-Aufruf (``KaliAdapter.run``)
ersetzt: er liefert die Tool-Ausgabe zurück bzw. schreibt die Ausgabedatei wie
das echte Tool. Scope-Check und Oversight sind nicht Teil dieser Tests und
werden nicht umgangen; geprüft wird ausschließlich die Parse-/Auswertungslogik.
"""
from __future__ import annotations

import ast
import asyncio
import inspect
import json
import textwrap
from pathlib import Path

import pytest

from antbb import greenbone
from antbb.parseutil import parse_json_robust
from antbb.tools import kali
from antbb.tools.kali import KaliAdapter, ToolResult
from antbb.tools.parsers import (
    PARSE_EMPTY, PARSE_OK, PARSE_PARTIAL, METHOD_EMBEDDED, METHOD_JSON, METHOD_JSONL,
    METHOD_LINES, safe_parse_json, safe_parse_jsonl,
)

ROOT = Path(__file__).resolve().parents[1]

# Format wie nuclei -jsonl (gekürzt auf die Felder, die der Adapter liest).
NUCLEI_LINE_1 = json.dumps({
    "template-id": "tech-detect", "matched-at": "https://example.test/",
    "info": {"name": "Wappalyzer Technology Detection", "severity": "info"}})
NUCLEI_LINE_2 = json.dumps({
    "template-id": "exposed-git", "matched-at": "https://example.test/.git/config",
    "info": {"name": "Git Config Exposure", "severity": "medium"}})


# ===========================================================================
# Helfer: safe_parse_json
# ===========================================================================
class TestSafeParseJson:
    def test_valid_json_object_is_ok(self):
        res = safe_parse_json('{"a": 1, "b": [1, 2]}', "kali.test")
        assert res.parse_status == PARSE_OK
        assert res.parse_warning is None
        assert res.method == METHOD_JSON
        assert res.data == {"a": 1, "b": [1, 2]}
        assert res.context == "kali.test"

    def test_valid_json_array_and_bytes_with_bom_are_ok(self):
        assert safe_parse_json("[{\"x\": 1}]").data == [{"x": 1}]
        res = safe_parse_json(b"\xef\xbb\xbf{\"k\": \"v\"}", "greenbone.report")
        assert res.parse_status == PARSE_OK and res.data == {"k": "v"}
        assert res.parse_warning is None

    @pytest.mark.parametrize("raw", [None, "", "   \n\t ", b"", bytearray()])
    def test_empty_and_none_input(self, raw):
        res = safe_parse_json(raw, "kali.test")
        assert res.parse_status == PARSE_EMPTY
        assert res.parse_warning is None
        assert res.data is None

    def test_mixed_banner_plus_json(self):
        raw = textwrap.dedent("""\
            __        __
            wpscan banner v3.8
            [+] URL: https://example.test/
            {"version": {"number": "6.4.2"}, "interesting_findings": []}
            [+] Finished
            """)
        res = safe_parse_json(raw, "kali.wpscan", expect=dict)
        assert res.parse_status == PARSE_PARTIAL
        assert res.method == METHOD_EMBEDDED
        assert res.data == {"version": {"number": "6.4.2"}, "interesting_findings": []}
        assert res.parse_warning.startswith("kali.wpscan: ")
        assert "json_decode" in res.parse_warning
        assert "1 eingebettete" in res.parse_warning

    def test_truncated_json_salvages_complete_inner_objects(self):
        raw = ('{"host": "example.test", "vulnerabilities": ['
               '{"id": "1", "msg": "Server leaks inodes via ETags"}, '
               '{"id": "2", "msg": "X-Frame-Options header missing"}, '
               '{"id": "3", "msg": "abgeschn')
        res = safe_parse_json(raw, "kali.nikto")
        assert res.parse_status == PARSE_PARTIAL
        assert res.method == METHOD_EMBEDDED
        assert res.data == [
            {"id": "1", "msg": "Server leaks inodes via ETags"},
            {"id": "2", "msg": "X-Frame-Options header missing"},
        ]
        assert "kali.nikto" in res.parse_warning and "json_decode" in res.parse_warning

    def test_unrecoverable_output_uses_line_fallback(self):
        raw = "ERROR: target unreachable\nstatus=failed\nretries: 3\n{\"broken\": "
        res = safe_parse_json(raw, "kali.ffuf")
        assert res.parse_status == PARSE_PARTIAL
        assert res.method == METHOD_LINES and res.is_line_fallback
        assert res.data["kv_guess"] == {"ERROR": "target unreachable",
                                        "status": "failed", "retries": "3"}
        assert res.data["lines"][0] == "ERROR: target unreachable"
        assert res.data["raw_excerpt"] == raw.strip()
        assert "kein JSON rettbar" in res.parse_warning

    def test_banner_brackets_are_not_salvaged_as_data(self):
        res = safe_parse_json("[+] scan done [1] [] {}", "kali.test")
        assert res.method == METHOD_LINES
        assert res.parse_status == PARSE_PARTIAL and res.parse_warning

    def test_schema_break_unexpected_type(self):
        res = safe_parse_json("[1, 2, 3]", "kali.wpscan", expect=dict)
        assert res.parse_status == PARSE_PARTIAL
        assert res.data == [1, 2, 3]
        assert "unexpected_type: list" in res.parse_warning

    def test_invalid_utf8_is_reported(self):
        res = safe_parse_json(b'{"a": "\xff"}', "kali.test")
        assert res.parse_status == PARSE_PARTIAL
        assert res.data == {"a": "\ufffd"}
        assert "utf8_decode" in res.parse_warning

    def test_as_meta_contains_status_and_warning(self):
        meta = safe_parse_json("noise {\"a\": 1}", "kali.x").as_meta()
        assert meta["parse_status"] == PARSE_PARTIAL
        assert meta["parse_context"] == "kali.x"
        assert meta["parse_method"] == METHOD_EMBEDDED
        assert meta["parse_warning"].startswith("kali.x: ")


# ===========================================================================
# Helfer: safe_parse_jsonl
# ===========================================================================
class TestSafeParseJsonl:
    def test_clean_jsonl_is_ok(self):
        res = safe_parse_jsonl(f"{NUCLEI_LINE_1}\n{NUCLEI_LINE_2}\n", "kali.nuclei")
        assert res.parse_status == PARSE_OK and res.parse_warning is None
        assert res.method == METHOD_JSONL
        assert [o["template-id"] for o in res.data] == ["tech-detect", "exposed-git"]

    def test_broken_line_is_counted_not_turned_into_object(self):
        raw = f"[INF] nuclei engine started\n{NUCLEI_LINE_1}\n{NUCLEI_LINE_2[:40]}\n"
        res = safe_parse_jsonl(raw, "kali.nuclei")
        assert res.parse_status == PARSE_PARTIAL
        assert len(res.data) == 1 and res.data[0]["template-id"] == "tech-detect"
        assert res.stats == {"items": 1, "broken_json_lines": 1, "non_json_lines": 1}
        assert "1 kaputte JSON-Zeile" in res.parse_warning
        assert "1 Textzeile" in res.parse_warning

    @pytest.mark.parametrize("raw", [None, "", "\n\n"])
    def test_empty_jsonl(self, raw):
        res = safe_parse_jsonl(raw, "kali.nuclei")
        assert res.parse_status == PARSE_EMPTY and res.data == []
        assert res.parse_warning is None


# ===========================================================================
# Kompatibilität: parseutil.parse_json_robust
# ===========================================================================
class TestParseutilCompat:
    def test_clean_and_empty(self):
        assert parse_json_robust('{"a": 1}') == ({"a": 1}, None)
        assert parse_json_robust("") == (None, "empty_output")

    def test_line_fallback_keeps_legacy_marker(self):
        obj, warn = parse_json_robust("kein json hier", expect=dict)
        assert obj["parse_warning"] is True and "raw_excerpt" in obj
        assert warn and "kein JSON rettbar" in warn

    def test_multiple_embedded_values_pick_first_expected_type(self):
        obj, warn = parse_json_robust('Antwort: {"steps": [1]} und {"x": 2}', expect=dict)
        assert obj == {"steps": [1]}
        assert warn and "2 eingebettete" in warn


# ===========================================================================
# Keine stillen except-Blöcke im Parser-Pfad
# ===========================================================================
def _silent_handlers(tree: ast.AST) -> list[int]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and all(
                isinstance(s, ast.Pass) for s in node.body):
            out.append(node.lineno)
    return out


@pytest.mark.parametrize("rel", ["antbb/tools/parsers.py", "antbb/parseutil.py"])
def test_no_silent_except_in_parser_modules(rel):
    tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
    assert _silent_handlers(tree) == []


@pytest.mark.parametrize("func", [
    greenbone.parse_json,
    KaliAdapter.nuclei, KaliAdapter.nikto, KaliAdapter.whatweb, KaliAdapter.wafw00f,
    KaliAdapter.ffuf, KaliAdapter.wpscan, KaliAdapter.searchsploit, KaliAdapter.trufflehog,
    KaliAdapter._read_json_file,
])
def test_no_silent_except_around_parsing(func):
    """Parse-Pfade: kein ``except: pass``.

    Einzige Ausnahme: das Aufräumen der Temp-Datei (``os.unlink``) im
    ``finally`` – das ist kein Parsen, ein Fehlschlag dort verliert keine Daten.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        only_unlink = all(
            isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)
            and getattr(s.value.func, "attr", "") == "unlink" for s in node.body)
        for h in node.handlers:
            silent = all(isinstance(s, ast.Pass) for s in h.body)
            assert not silent or only_unlink, (
                f"stiller except in {func.__qualname__} (Zeile {h.lineno})")


def test_jsonl_log_prefixes_are_text_not_broken_json():
    raw = "[INF] Templates loaded\n[WRN] rate limit\n[+] done\n[]\n[{\"a\": 1}]\n"
    res = safe_parse_jsonl(raw, "kali.nuclei")
    assert res.stats == {"items": 2, "broken_json_lines": 0, "non_json_lines": 3}
    assert res.data == [[], [{"a": 1}]]


# ===========================================================================
# kali.py: parse_warning wird durchgereicht
# ===========================================================================
class _Ctx:
    """Minimaler AgentContext: sammelt Logzeilen."""

    def __init__(self):
        self.lines: list[str] = []
        self.active = True
        self.fuzz = False

    def log(self, msg: str) -> None:
        self.lines.append(msg)


def _adapter(monkeypatch, *, stdout: str = "", out_file: str | None = None) -> KaliAdapter:
    """KaliAdapter, dessen Subprozess-Aufruf die gegebene Tool-Ausgabe liefert."""
    ad = KaliAdapter(_Ctx())

    async def _run(tool, argv, *, target, timeout=120.0, offensive=False, input_text=None):
        argv = [str(a) for a in argv]
        if out_file is not None:
            for flag in ("-output", "-o"):
                if flag in argv:
                    Path(argv[argv.index(flag) + 1]).write_text(out_file, encoding="utf-8")
        return ToolResult(tool=tool, available=True, ran=True, returncode=0,
                          stdout=stdout, command=[tool, *argv])

    monkeypatch.setattr(ad, "run", _run)
    return ad


def test_kali_nuclei_clean_jsonl_has_no_warning(monkeypatch):
    ad = _adapter(monkeypatch, stdout=f"{NUCLEI_LINE_1}\n{NUCLEI_LINE_2}\n")
    out = asyncio.run(ad.nuclei("https://example.test/"))
    assert [f.evidence["template_id"] for f in out] == ["tech-detect", "exposed-git"]
    assert ad.parse_events == []
    assert all("parse_warning" not in f.evidence for f in out)


def test_kali_nuclei_broken_line_passes_parse_warning(monkeypatch):
    ad = _adapter(monkeypatch, stdout=f"{NUCLEI_LINE_1}\n{NUCLEI_LINE_2[:50]}\n")
    out = asyncio.run(ad.nuclei("https://example.test/"))
    # Nur die echte Zeile wird zum Fund – kein Pseudo-Fund aus der kaputten Zeile.
    assert len(out) == 1 and out[0].evidence["template_id"] == "tech-detect"
    assert out[0].evidence["parse_status"] == PARSE_PARTIAL
    assert out[0].evidence["parse_warning"].startswith("kali.nuclei: ")
    assert len(ad.parse_events) == 1
    assert ad.parse_events[0]["parse_context"] == "kali.nuclei"
    assert any("parse_warning=kali.nuclei" in ln for ln in ad.ctx.lines)


def test_kali_nikto_truncated_file_salvages_and_warns(monkeypatch):
    truncated = ('{"host": "example.test", "vulnerabilities": ['
                 '{"id": "999957", "msg": "The anti-clickjacking X-Frame-Options header is not present.", '
                 '"url": "https://example.test/"}, {"id": "9999', )[0]
    ad = _adapter(monkeypatch, out_file=truncated)
    out = asyncio.run(ad.nikto("https://example.test/"))
    assert len(out) == 1
    assert out[0].evidence["id"] == "999957"
    assert out[0].evidence["parse_status"] == PARSE_PARTIAL
    assert "kali.nikto" in out[0].evidence["parse_warning"]
    assert ad.parse_events and ad.parse_events[0]["parse_method"] == METHOD_EMBEDDED


def test_kali_nikto_empty_output_is_honest_empty(monkeypatch):
    ad = _adapter(monkeypatch, out_file="")
    assert asyncio.run(ad.nikto("https://example.test/")) == []
    assert ad.parse_events == []


def test_kali_wafw00f_garbage_is_visible_not_silent(monkeypatch):
    ad = _adapter(monkeypatch, out_file="Traceback (most recent call last):\nKeyError: 'url'\n")
    assert asyncio.run(ad.wafw00f("https://example.test/")) == []
    assert len(ad.parse_events) == 1
    ev = ad.parse_events[0]
    assert ev["parse_status"] == PARSE_PARTIAL and ev["parse_method"] == METHOD_LINES
    assert any("kali.wafw00f" in ln and "parse_warning=" in ln for ln in ad.ctx.lines)


def test_kali_wpscan_banner_plus_json(monkeypatch):
    stdout = ("_______________\n  WordPress Security Scanner\n"
              '{"version": {"number": "6.4.2", "status": "latest"}}\n')
    ad = _adapter(monkeypatch, stdout=stdout)
    out = asyncio.run(ad.wpscan("https://example.test/"))
    assert len(out) == 1 and out[0].evidence["version"] == "6.4.2"
    assert out[0].evidence["parse_status"] == PARSE_PARTIAL
    assert out[0].evidence["parse_warning"].startswith("kali.wpscan: ")


def test_kali_module_has_no_legacy_iter_jsonl():
    # Der alte Iterator verwarf Warnungen per ``pass`` und lieferte Marker-Objekte,
    # aus denen nuclei Pseudo-Funde baute; er ist durch safe_parse_jsonl ersetzt.
    assert not hasattr(kali, "_iter_jsonl")


# ===========================================================================
# greenbone.parse_json: parse_warning wird durchgereicht
# ===========================================================================
def _gvm_result(rid: str, host: str, sev: str, name: str) -> dict:
    return {"id": rid, "host": host, "port": "443/tcp", "severity": sev,
            "nvt": {"oid": f"1.3.6.1.4.1.25623.1.0.{rid}", "name": name, "family": "Web"}}


GVM_REPORT = {"report_id": "rep-1", "results": [
    _gvm_result("100", "10.0.0.5", "7.5", "TLS Weak Cipher"),
    _gvm_result("101", "10.0.0.6", "5.0", "HTTP Server Banner"),
]}


def test_greenbone_clean_json_is_ok():
    rep = greenbone.parse_json(json.dumps(GVM_REPORT))
    assert rep.meta["parse_status"] == PARSE_OK
    assert "parse_warning" not in rep.meta
    assert len(rep.results) == 2 and rep.meta["report_id"] == "rep-1"
    assert rep.summary()["parse_status"] == PARSE_OK


def test_greenbone_banner_plus_json_passes_warning():
    raw = "gvm-cli 24.1 — export\n" + json.dumps(GVM_REPORT) + "\n-- end --\n"
    rep = greenbone.parse_json(raw)
    assert len(rep.results) == 2
    assert rep.meta["parse_status"] == PARSE_PARTIAL
    assert rep.meta["parse_warning"].startswith("greenbone.report: ")
    s = rep.summary()
    assert s["parse_warning"] == rep.meta["parse_warning"]
    assert any(w.startswith("Parse-Fallback:") for w in s["warnings"])


def test_greenbone_truncated_json_salvages_results():
    full = json.dumps({"report_id": "rep-2", "results": [
        _gvm_result("200", "10.0.0.7", "9.8", "RCE in Example"),
        _gvm_result("201", "10.0.0.8", "6.1", "XSS in Example")]})
    raw = full[: full.index('"201"') + 12]   # mitten im zweiten Result abgeschnitten
    rep = greenbone.parse_json(raw)
    assert rep.meta["parse_status"] == PARSE_PARTIAL
    assert [r.host for r in rep.results] == ["10.0.0.7"]
    assert "greenbone.report" in rep.meta["parse_warning"]


def test_greenbone_unreadable_json_line_fallback_redacted():
    raw = "{ kaputt\npassword=Sup3rGeheim\nCVE-2024-3094 erwähnt\n"
    rep = greenbone.parse_json(raw)
    assert rep.results == []
    assert rep.meta["parse_status"] == PARSE_PARTIAL
    assert rep.meta["parse_method"] == METHOD_LINES
    assert rep.meta["cve_guess"] == ["CVE-2024-3094"]
    assert "Sup3rGeheim" not in rep.meta["raw_excerpt"]
    assert "Sup3rGeheim" not in json.dumps(rep.meta["kv_guess"])
    assert any(w.startswith("Parse-Fallback:") for w in rep.warnings)


@pytest.mark.parametrize("raw", ["", None])
def test_greenbone_empty_input(raw):
    rep = greenbone.parse_json(raw)
    assert rep.meta["parse_status"] == PARSE_EMPTY
    assert rep.results == [] and "Report-JSON ist leer." in rep.warnings


def test_greenbone_clean_json_without_results_still_errors():
    with pytest.raises(greenbone.GvmError):
        greenbone.parse_json('{"report": {"name": "nothing here"}}')
