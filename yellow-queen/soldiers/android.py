"""Soldat android: APK/DEX – Manifest/Code via apktool + jadx wenn vorhanden."""
from __future__ import annotations

import zipfile

from .base import Ctx, SoldierResult, first_lines, redact_tree, run_cli
from .. import config

NAME = "android"
RISKY = ["READ_SMS", "SEND_SMS", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "READ_CONTACTS", "SYSTEM_ALERT_WINDOW",
         "REQUEST_INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE", "READ_CALL_LOG"]


def run(ctx: Ctx) -> SoldierResult:
    c = ctx.classification
    d = c["details"]
    res = SoldierResult(NAME, "apk-android-re", "Android-Soldat")
    s = str(ctx.sample)
    heavy = config.HEAVY_TIMEOUT
    at = run_cli(ctx, res, "apktool", ["apktool"], ["d", "-f", "-o", str(ctx.evidence_dir / "apktool_out"), s], "android_apktool.log", heavy)
    jd = run_cli(ctx, res, "jadx", ["jadx"], ["-d", str(ctx.evidence_dir / "jadx_out"), "--no-res", s], "android_jadx.log", heavy)
    for sub in ("apktool_out", "jadx_out"):  # Secrets nie speichern: Textdateien nachträglich schwärzen
        redact_tree(ctx.evidence_dir / sub)
    perms: list[str] = []
    mani = ctx.evidence_dir / "apktool_out" / "AndroidManifest.xml"
    if mani.exists():
        txt = mani.read_text("utf-8", "ignore")
        import re
        perms = sorted(set(re.findall(r'uses-permission[^>]*android:name="([^"]+)"', txt)))
        (ctx.evidence_dir / "android_permissions.txt").write_text("\n".join(perms), encoding="utf-8")
        res.evidence.append("android_permissions.txt")
    risky = [p for p in perms if any(r in p for r in RISKY)]
    entries = []
    if zipfile.is_zipfile(ctx.sample):
        with zipfile.ZipFile(ctx.sample) as z:
            entries = z.namelist()[:15]
    res.facts.update(apk=d, permissions=perms[:40], risky_permissions=risky, zip_head=entries,
                     apktool_log=first_lines(at, 4) if at else [], jadx_log=first_lines(jd, 4) if jd else [])
    if not (at or jd):
        res.status = "partial"
    res.warum = ("apktool dekodiert Manifest und Ressourcen, jadx liefert lesbaren Java-Code – zusammen der schnellste Überblick über eine App. "
                 "Native .so-Libs kommen erst danach mit Ghidra/rizin, sonst fehlt die Karte, welche Java-Methode sie aufruft.")
    res.fund = (f"{d.get('entries', '?')} Einträge, DEX: {', '.join(d.get('dex', [])) or 'roh'}, Native Libs (ABIs): {', '.join(d.get('native_libs', [])) or 'keine'}, "
                f"signiert: {'ja' if d.get('signed') else 'nein/unbekannt'}. "
                + (f"{len(perms)} Berechtigungen, davon heikel: {', '.join(risky) or 'keine'}. " if perms else "Manifest nicht dekodiert (apktool fehlt/fehlgeschlagen). ")
                + "Berechtigungen zeigen, worauf die App am Gerät zugreifen darf.")
    res.next = ["Manifest: Activities/Services/Receiver durchsehen", "jadx-Quelltext nach Netzwerk/Krypto/Einstiegspunkt durchsuchen", "Native Libs gezielt analysieren"]
    res.summary_de = f"Android: {len(perms)} Berechtigungen ({len(risky)} heikel), apktool={'ja' if at else 'nein'}, jadx={'ja' if jd else 'nein'}"
    return res
