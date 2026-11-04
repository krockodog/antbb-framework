"""DE/EN catalogs stay in lockstep, and the switcher is on the converted pages."""
import json
import re
from pathlib import Path

from antbb.i18n import DEFAULT, catalogs, resolve_lang, t

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "antbb" / "web" / "templates"
CONVERTED = (
    "base.html",
    "login.html",
    "assets.html",
    "trash.html",
    "history.html",
    "reports.html",
    "server-history.html",
)
GERMAN = re.compile(r"[äöüÄÖÜß]|(?<![A-Za-z])(Anmelden|Königin|Papierkorb|Hinweis)(?![A-Za-z])")


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


def test_converted_templates_have_no_hardcoded_german():
    for name in CONVERTED:
        text = (TEMPLATES / name).read_text(encoding="utf-8")
        text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        assert not GERMAN.search(text), name
