"""DE/EN catalogs stay in lockstep, and converted pages have no hardcoded German."""
import re
from pathlib import Path

from antbb.i18n import DEFAULT, catalogs, resolve_lang, t

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "antbb" / "web" / "templates"
STATIC = ROOT / "antbb" / "web" / "static"
ALLOW = ROOT / "antbb" / "locale" / "allowlist.txt"
CONVERTED = (
    "base.html",
    "login.html",
    "assets.html",
    "trash.html",
    "history.html",
    "reports.html",
    "server-history.html",
    "index.html",
    "blue.html",
    "brain.html",
    "target.html",
    "wlan.html",
    "server-wlan.html",
)
JS = (
    "red_cards.js",
    "blue_cards.js",
    "blue_greenbone.js",
    "blue_remediation.js",
    "blue.js",
    "wlan.js",
    "wlan_features.js",
    "wlan_heatmap.js",
    "wlan_offensive.js",
    "wlan_scope.js",
    "orchestrate.js",
    "soldiers.js",
    "rating.js",
    "scan-depth.js",
    "hub-real.js",
    "attackpath.js",
    "antmap.js",
    "antmap_colony.js",
    "brain/nodes-panel.js",
    "brain/queens.js",
    "brain/runs.js",
    "brain/superhirn-log.js",
    "brain/queen-viewer.js",
    "brain/ants.js",
    "brain/ants3d.js",
)
GERMAN = re.compile(
    r"[äöüÄÖÜß]|(?<![A-Za-z])(Anmelden|Königin|Papierkorb|Hinweis)(?![A-Za-z])"
)


def test_catalogs_have_identical_nonempty_keys():
    books = catalogs()
    assert set(books) == {"de", "en"}
    assert set(books["de"]) == set(books["en"])
    assert books["de"]
    for code, book in books.items():
        for key, value in book.items():
            assert value.strip(), f"{code}:{key} is empty"
            assert value != key


def test_unknown_language_falls_back_to_german():
    assert resolve_lang("zz") == DEFAULT == "de"
    assert resolve_lang("zz", "zz", "fr-FR, xx") == "de"
    assert resolve_lang("en") == "en"
    assert resolve_lang(None, "en") == "en"
    assert resolve_lang(None, None, "fr, en-US") == "en"
    assert "strafbar" in t("legal.full", "de").lower() or "STRAFBAR" in t("legal.full", "de")
    english = t("legal.full", "en")
    assert "CFAA" in english and "202a" in english
    assert "not a substitute" in t("legal.not_substitute", "en").lower()
    assert "default-deny" in t("scope.default_deny", "en").lower()
    assert t("oversight.confirm", "en") != t("oversight.confirm", "de")
    german_hint = t("bind.local_only", "de")
    english_hint = t("bind.local_only", "en")
    assert "ANTBB_EXPOSE=0" in german_hint and "ANTBB_EXPOSE=1" in german_hint
    assert "ANTBB_EXPOSE=0" in english_hint and "ANTBB_EXPOSE=1" in english_hint
    assert "SSH" in german_hint and "SSH" in english_hint
    assert german_hint != english_hint


def test_switcher_renders_and_preserves_the_query():
    from fastapi.testclient import TestClient
    from antbb.web.app import app

    with TestClient(app) as client:
        page = client.get("/login?lang=en&next=/assets")
        assert page.status_code == 200
        assert "DE" in page.text and "EN" in page.text
        assert "Sign in" in page.text
        assert "lang=de" in page.text and "next=%2Fassets" in page.text or "next=/assets" in page.text
        assert "antbb_lang=en" in page.headers.get("set-cookie", "")
        client.cookies.set("antbb_lang", "en")
        again = client.get("/login")
        assert "Sign in" in again.text
    with TestClient(app) as fresh:
        unknown = fresh.get("/login?lang=zz")
        assert "Anmelden" in unknown.text


def _allow_markers():
    markers = []
    for raw in ALLOW.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, marker = line.split(":", 1)
        markers.append((name.strip(), marker.strip()))
    return markers


def _visible_lines(path: Path):
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    markers = _allow_markers()
    rel = str(path)
    for line in text.splitlines():
        code = re.sub(r"//.*", "", line)
        if any(rel.endswith(name) and marker in line for name, marker in markers):
            continue
        if GERMAN.search(code):
            yield code.strip()


def test_converted_templates_and_scripts_have_no_hardcoded_german():
    paths = [TEMPLATES / name for name in CONVERTED]
    paths += [STATIC / name for name in JS]
    leftovers = []
    for path in paths:
        hits = list(_visible_lines(path))
        if hits:
            leftovers.append(f"{path.name}: {hits[0]}")
    assert not leftovers, leftovers


def test_every_template_has_the_language_switcher():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    assert "lang-switch" in base
    assert "lang_href('de')" in base and "lang_href('en')" in base
    for path in TEMPLATES.glob("*.html"):
        if path.name == "base.html":
            continue
        text = path.read_text(encoding="utf-8")
        assert 'extends "base.html"' in text, path.name
