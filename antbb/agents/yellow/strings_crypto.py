"""Yellow-Soldat: Strings- & Krypto-Konstanten-Jagd.

Extrahiert rein lesend druckbare Strings (>=4) aus einer Probe und markiert verdaechtige Hinweise (URLs, Pfade, bekannte Krypto-Konstanten-Hinweise). Secrets werden NICHT ausgegeben, nur gezaehlt/kategorisiert.

Rein lesend / non-destruktiv. Tiefe oder dynamische Schritte laufen NUR ueber
das Oversight-Gate (ctx.active). Mit Erklaerpfad: zu jedem Schritt die Begruendung.
"""
from __future__ import annotations

from .base import YellowAgent, AgentFinding, Playbook, Task


_HINTS = ("http://", "https://", "ftp://", "/bin/", "/etc/", "cmd.exe",
          "powershell", "BEGIN RSA", "BEGIN PRIVATE", "-----BEGIN")
_CRYPTO = ("AES", "RC4", "DES", "SHA256", "MD5", "XTEA", "Salsa", "ChaCha")


class YellowStringsAnt(YellowAgent):
    name = "yellow-strings"
    specialty = "yellow-strings-crypto-hunt"
    role = ("Strings- und Krypto-Konstanten-Jagd: druckbare Strings extrahieren "
            "und verdaechtige Hinweise kategorisieren. Secrets werden redigiert.")
    yellow_phases = ("triage", "static")
    playbooks = (
        Playbook("strings-crypto-hunt", "defensive", False,
                 ["printable-strings", "indicator-scan", "crypto-constant-hint"],
                 "Druckbare Strings (>=4) extrahieren, Indikatoren (URLs/Pfade) und "
                 "Krypto-Hinweise kategorisieren. Secrets redigiert (nur Zaehlung)."),
    )

    async def work(self, task: Task) -> list[AgentFinding]:
        import os, re
        findings: list[AgentFinding] = []
        self.ctx.log("[yellow-strings] 🧵 Strings-/Krypto-Jagd (read-only).")
        sp = self.sample_path(task)
        if not sp:
            findings.append(AgentFinding(
                agent=self.name, title="Keine Probe uebergeben",
                category="yellow-strings", severity="info", asset="-",
                description="Erklaerpfad: ohne Probe keine String-Extraktion.",
                evidence={}, status="REFERENZ", dedup_key="yellow-strings:no-sample"))
            return findings
        data = open(sp, "rb").read()
        strs = re.findall(rb"[\x20-\x7e]{4,}", data)
        total = len(strs)
        texts = [s.decode("ascii", "ignore") for s in strs]
        indicators = sorted({h for t in texts for h in _HINTS if h.lower() in t.lower()})
        crypto = sorted({c for t in texts for c in _CRYPTO if c.lower() in t.lower()})
        self.ctx.log(f"[yellow-strings] {total} Strings, {len(indicators)} Indikator(en), {len(crypto)} Krypto-Hinweis(e).")
        findings.append(AgentFinding(
            agent=self.name, title=f"[{total} Strings] {os.path.basename(sp)}",
            category="yellow-strings", severity=("low" if indicators else "info"),
            asset=os.path.basename(sp),
            description="Erklaerpfad: druckbare Strings extrahiert und kategorisiert. "
                        "Konkrete Secret-Werte werden bewusst NICHT aufgenommen.",
            evidence={"string_count": total, "indicators": indicators,
                      "crypto_hints": crypto},
            status="BESTÄTIGT(PASSIV)", dedup_key=f"yellow-strings:{os.path.basename(sp)}"))
        return findings
