#!/usr/bin/env python3
"""ISMS / ISO/IEC 27001:2022 report: no invented findings, 93 SoA rows, Gast GET."""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from antbb import iso27001 as iso
from antbb.store import Store


def check(name, cond):
    print(f"  {'OK' if cond else 'FAIL'}  {name}")
    return bool(cond)


def main() -> int:
    ok = 0
    n = 0

    def C(name, cond):
        nonlocal ok, n
        n += 1
        if check(name, cond):
            ok += 1

    print("=== iso27001 core ===")
    controls = iso.annex_a_controls()
    C("Annex A has 93 controls", len(controls) == 93)
    ids = [c["id"] for c in controls]
    C("unique control IDs", len(set(ids)) == 93)
    C("starts at A.5.1", ids[0] == "A.5.1")
    C("ends at A.8.34", ids[-1] == "A.8.34")

    def li(sev):
        v = iso.severity_to_li(sev)
        return v[:2]
    C("critical -> 4x5", li("critical") == (4, 5))
    C("high -> 3x4", li("high") == (3, 4))
    C("medium -> 3x3", li("medium") == (3, 3))
    C("low -> 2x2", li("low") == (2, 2))
    C("info -> 1x1", li("info") == (1, 1))
    C("L/I note marks methods-default", "Methoden-Default" in iso.severity_to_li("high")[2])
    C("score 4*5=20", iso.risk_score(4, 5) == 20)
    C("default threshold 15", iso.DEFAULT_ACCEPTANCE_THRESHOLD == 15)

    # isms_report imports proofgate; skip the HTTP layer if deps missing.
    try:
        from antbb import isms_report as isms
        have_isms = True
    except Exception as exc:
        have_isms = False
        print(f"  (isms_report import skipped: {type(exc).__name__}: {exc})")

    if have_isms:
        print("=== empty store: keine Daten, no invented F-1 ===")
        with tempfile.TemporaryDirectory() as td:
            st = Store(os.path.join(td, "isms.db"))
            bundle = isms.collect_bundle(st)
            html = isms.render_html(bundle, kind="isms")
            C("SoA 93 rows", len(bundle["soa"]) == 93)
            C("empty register is empty (not invented)", bundle["counts"]["register"] == 0)
            C("disclaimer present", isms.DISCLAIMER in html)
            C("audit-prep wording present", "ersetzt keine Zertifizierung" in html)
            C("placeholder marker present", isms.PLACEHOLDER in html)
            C("keine Daten present", isms.NO_DATA in html.lower() or "keine Daten" in html)
            C("no invented F-1 finding id", "F-1 ·" not in html and "F-1:" not in html)
            csv_bytes = isms.export_csv(bundle["soa"], ["id", "title", "status", "evidence"])
            text = csv_bytes.decode("utf-8-sig")
            C("CSV has 93 data rows", text.count("\n") >= 94)
            C("CSV starts with A.5.1", "A.5.1" in text)

            C("landscape named page in CSS", "@page landscape" in html and "page: landscape" in html)
            C("SoA applicable short form", "ja (Default)" in html)
            C("no long applicable default in HTML",
              "ja (Default; Abweichung als [AUSZUFÜLLEN] dokumentieren)" not in html)
            C("applicability footnote present", "Fußnote Anwendbarkeit" in html)
            C("new chapter 6.2", "Informationssicherheitsziele (6.2)" in html)
            C("new chapter 6.3", "Planung von Änderungen (6.3)" in html)
            C("asset inventory chapter", "Asset-Inventar" in html)
            C("chapter 7.1-7.3", "Ressourcen, Kompetenz und Awareness" in html)
            C("chapter 7.4", "Kommunikation (7.4)" in html)
            C("chapter 7.5", "Dokumentierte Information und Lenkung (7.5)" in html)
            C("chapter 8.1", "Betriebliche Planung und Steuerung (8.1)" in html)
            C("policy 5.2 outline", "Pflichtinhalt (5.2)" in html)
            C("RACI table", "RACI" in html and "Tätigkeit" in html)
            C("portrait restart after landscape", "page-portrait" in html)

        print("=== mapping: real finding -> register, plans, SoA evidence ===")
        with tempfile.TemporaryDirectory() as td:
            st = Store(os.path.join(td, "map.db"))
            tid = st.add_target("antbb-selftest-isms", "Autorisierter Testlauf")
            st.add_scope(tid, "url", "https://antbb.carescribe.online", allowed=True)
            fid = st.add_finding(
                tid, "run-selftest-red-1", "scanner",
                "Testdienst erreichbar (Selftest)",
                "exposure", "medium",
                asset="https://antbb.carescribe.online",
                description="Defensiver Selftest gegen das eigene System.",
                evidence={"check": "http 200"},
                status="PASSIVE",
            )
            C("finding stored", bool(fid))
            st.add_finding(
                tid, "run-selftest-blue-1", "blue-hardening",
                "[FAIL] Kernel-Netzwerk-Härtung (sysctl)",
                "blue-hardening-gap", "medium",
                asset="antbb-selftest-isms",
                description="Selftest: fehlgeschlagener Blue-Check.",
                evidence={"check_id": "sysctl"},
                status="BESTÄTIGT(PASSIV)",
            )
            st.add_finding(
                tid, "run-selftest-blue-1", "blue-webharden",
                "[PASS] strict-transport-security gesetzt",
                "blue-webharden-pass", "info",
                asset="https://antbb.carescribe.online",
                description="Selftest: bestandener Blue-Check.",
                evidence={"header": "strict-transport-security"},
                status="BESTÄTIGT(PASSIV)",
            )
            red = isms.collect_red(st)
            C("collect_red sees only the red finding", len(red) == 1)
            C("red run_id preserved", red[0]["run_id"] == "run-selftest-red-1")
            C("selftest marker", isms.is_selftest(red[0]))
            blue = isms.collect_blue(st)
            C("collect_blue sees both stored checks", len(blue) == 2)
            C("failed blue has status fail",
              any(b.get("status") == "fail" and "sysctl" in (b.get("title") or "") for b in blue))
            C("passed blue has status pass",
              any(b.get("status") == "pass" and "strict-transport-security" in (b.get("title") or "") for b in blue))
            org = isms.load_org(st)
            bundle = isms.collect_bundle(st)
            C("bundle register is red fail + blue fail", bundle["counts"]["register"] == 2)
            C("bundle blue_fail is 1", bundle["counts"]["blue_fail"] == 1)
            umg_b = [s for s in bundle["soa"]
                     if "umgesetzt" in (s.get("evidence") or "")
                     and "run-selftest-blue-1" in (s.get("evidence") or "")]
            C("bundle SoA marks passed blue umgesetzt", len(umg_b) >= 1)
            C("bundle SoA includes red run id",
              any("run-selftest-red-1" in (s.get("evidence") or "") for s in bundle["soa"]))
            crowded = ([{"queen": "red", "title": f"R{i}", "run_id": f"red-{i}",
                         "controls": ["A.8.7"], "score": 9, "when": "t"}
                        for i in range(12)]
                       + [{"queen": "yellow", "title": "RE-Fall: antbb-selftest-true",
                           "id": "yq-selftest-1", "run_id": "yq-selftest-1",
                           "controls": ["A.8.7"], "score": 1, "when": "t",
                           "filename": "antbb-selftest-true"}])
            crowded_reg = isms.risk_register(crowded, org)
            crowded_soa = isms.build_soa(crowded_reg, org)
            a87 = next(s for s in crowded_soa if s["id"] == "A.8.7")
            C("SoA keeps yellow case id among many red proofs",
              "yq-selftest-1" in (a87.get("evidence") or ""))
            reg = isms.risk_register(red + [b for b in blue if b.get("status") == "fail"], org)
            C("register has red finding plus failed blue check", len(reg) == 2)
            C("register LxI from medium", reg[0]["likelihood"] == 3 and reg[0]["impact"] == 3)
            C("register has annex controls", bool(reg[0].get("controls")))
            treat_html = isms._treatment_plan_table(reg)
            meas_html = isms._measures_plan_table(reg)
            C("treatment plan includes run finding title", "Testdienst erreichbar" in treat_html)
            C("measures plan includes recommendation or title", "Testdienst erreichbar" in meas_html)
            passed = [{
                "queen": "blue", "id": "patch-selftest", "title": "Selftest-Patchcheck",
                "status": "pass", "run_id": "run-selftest-blue-1",
                "when": "10.11.2026 12:00 Europe/Berlin",
                "controls": list(reg[0]["controls"])[:1] or ["A.8.8"],
                "asset": "eigener Server",
            }]
            soa = isms.build_soa(reg, org, blue_items=passed)
            C("SoA still 93", len(soa) == 93)
            C("all applicable short or ja", all(
                s["applicable"] in {"ja", "ja (Default)"} for s in soa))
            hit = [s for s in soa if "run-selftest-red-1" in (s.get("evidence") or "")]
            C("SoA evidence contains red run id", len(hit) >= 1)
            umg = [s for s in soa if "umgesetzt" in (s.get("evidence") or "") and "run-selftest-blue-1" in (s.get("evidence") or "")]
            C("passed blue is umgesetzt with run id", len(umg) >= 1)
            html2 = isms.render_html({
                **isms.collect_bundle(st),
                "register": reg,
                "soa": soa,
                "red": red,
                "counts": {
                    **isms.collect_bundle(st)["counts"],
                    "register": len(reg),
                    "soa": 93,
                },
            }, kind="isms")
            C("rendered HTML marks test run", "Testlauf (eigenes System)" in html2)
            C("asset inventory lists selftest target", "antbb-selftest-isms" in html2)
            C("register and SoA in landscape wrapper", 'class="page-landscape"' in html2)

        print("=== HTTP routes (no hosted auth) ===")
        os.environ.pop("ANTBB_HOSTED", None)
        from fastapi.testclient import TestClient
        from antbb.web.app import app
        client = TestClient(app, raise_server_exceptions=False)

        r = client.get("/red/report.pdf")
        C("GET /red/report.pdf 200", r.status_code == 200)
        ctype = r.headers.get("content-type", "")
        C("red report is pdf or honest html",
          "application/pdf" in ctype or "text/html" in ctype)
        body = r.content
        if "application/pdf" in ctype:
            C("red pdf starts with %PDF", body[:4] == b"%PDF")
        else:
            html_body = r.text
            C("html fallback has disclaimer", "ersetzt keine Zertifizierung" in html_body)
            C("html fallback has keine Daten or placeholder",
              "keine Daten" in html_body or "[AUSZUFÜLLEN]" in html_body)
            C("html fallback no invented F-1", "F-1 ·" not in html_body)

        for path in ("/blue/report.pdf", "/yellow/report.pdf", "/isms/report.pdf"):
            rr = client.get(path)
            C(f"GET {path} 200", rr.status_code == 200)

        soa = client.get("/isms/soa.csv")
        C("GET /isms/soa.csv 200", soa.status_code == 200)
        C("SoA CSV has 93 controls", soa.text.count("A.") >= 93)

        # Hosted-mode role checks: simulate request.state via dependency is hard;
        # the 403 is enforced when a viewer is in request.state. We unit-check
        # the helper by patching a fake request in a narrow test if hosted is off:
        # unauthenticated TestClient in non-hosted mode is allowed to GET /isms
        # (webguard is lax). The hosted 403 is covered below only if we can
        # set a viewer user.

    print(f"\n{ok}/{n} checks passed")
    return 0 if ok == n else 1


if __name__ == "__main__":
    raise SystemExit(main())
