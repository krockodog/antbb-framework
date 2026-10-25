"""Gelbe Klassifikation. Nur der Name, keine Datei, keine Werkzeugläufe."""

from __future__ import annotations

from typing import Any

KINDS = ("pe", "dotnet", "apk", "elf", "hex", "dos")

KIND_LABEL = {
    "pe": "PE",
    "dotnet": ".NET",
    "apk": "APK",
    "elf": "ELF",
    "hex": "HEX",
    "dos": "DOS",
    "unknown": "unbekannt",
}


def _step(order: int, title: str, tool: str, why: str, dynamic: bool) -> dict[str, Any]:
    return {
        "order": order,
        "title": title,
        "tool": tool,
        "dynamic": dynamic,
        "erklaerbaerin": why,
        "stub": True,
        "stub_note": "geplant/Mock",
    }


def _plans(kind: str) -> list[dict[str, Any]]:
    hull = _step(
        1,
        "Hülle bestimmen",
        "Namen und angegebene Art lesen",
        "Ich bleibe bei der Hülle. Der Name sagt mir das Format, noch nicht, was die Probe tut. Eine Datei öffne ich in diesem Stand nicht.",
        False,
    )
    plans: dict[str, list[dict[str, Any]]] = {
        "pe": [
            hull,
            _step(
                2,
                "PE-Kopf planen",
                "Kopfbild (geplant)",
                "Ich würde als Nächstes Maschine, Subsystem und Zeitstempel im Kopf ansehen. Das bleibt ein Plan, damit ich die Abschnitte nicht rate.",
                True,
            ),
            _step(
                3,
                "Abschnitte planen",
                "Abschnittsliste (geplant)",
                "Die Abschnitte sagen, wo Code und Daten liegen würden. Ich notiere die Reihenfolge, ich schneide nichts auf.",
                True,
            ),
            _step(
                4,
                "Importnamen planen",
                "Importliste (geplant)",
                "Ich stelle die Importnamen an das Ende, weil sie zeigen, welche Bibliotheken die Datei erwarten würde. Ohne den Kopf davor wäre die Liste blind.",
                True,
            ),
        ],
        "dotnet": [
            hull,
            _step(
                2,
                "CLR-Hinweis planen",
                "Laufzeithinweis (geplant)",
                "Ich prüfe den Laufzeit-Hinweis zuerst. Sonst würde ich die Datei fälschlich wie ein natives PE behandeln.",
                True,
            ),
            _step(
                3,
                "Assembly-Namen planen",
                "Assembly (geplant)",
                "Ich will den Assembly-Namen vor den Typen, weil er die Probe einer Familie zuordnet und die Typübersicht sonst ins Leere läuft.",
                True,
            ),
            _step(
                4,
                "Typübersicht planen",
                "Typübersicht (geplant)",
                "Ich lege die Typübersicht an das Ende. Sie erklärt den Bau, und ich führe dabei nichts aus.",
                True,
            ),
        ],
        "apk": [
            hull,
            _step(
                2,
                "Paketform planen",
                "Container (geplant)",
                "Ein APK ist ein Paket. Ich plane den Blick auf den Container, nicht auf ein Entpacken in diesem Stand.",
                True,
            ),
            _step(
                3,
                "Manifest-Lage planen",
                "Manifest (geplant)",
                "Ich stelle das Manifest vor die Bibliotheken, weil es Paket und Komponenten benennt und die Bibliotheken sonst ohne Rahmen dastehen.",
                True,
            ),
            _step(
                4,
                "Native Bibliotheken benennen",
                "Native Bibliotheken (geplant)",
                "Ich würde native Anteile nur benennen. Ausführen bleibt aus, weil ein Name keine Erlaubnis ist.",
                True,
            ),
        ],
        "elf": [
            hull,
            _step(
                2,
                "Klasse und Maschine planen",
                "ELF-Kopf (geplant)",
                "Ich lese Klasse und Maschine zuerst. Ohne sie wäre jede spätere Symbolsuche blind.",
                True,
            ),
            _step(
                3,
                "Programmkopf planen",
                "Programmkopf (geplant)",
                "Der Programmkopf zeigt die ladbaren Stücke. Ich plane ihn vor den Symbolen, weil er die Grenzen setzt.",
                True,
            ),
            _step(
                4,
                "Dynamische Symbole planen",
                "Symbolnamen (geplant)",
                "Ich setze die Symbolnamen an das Ende. Sie bleiben eine Liste, kein Lauf, und ergeben erst nach dem Programmkopf Sinn.",
                True,
            ),
        ],
        "hex": [
            hull,
            _step(
                2,
                "Textformat planen",
                "Intel-HEX als Text (geplant)",
                "HEX ist Text mit Adressen, kein ausgeführtes Programm. Ich würde die Zeilenform prüfen, bevor ich Adressen glaube.",
                True,
            ),
            _step(
                3,
                "Adresslücken planen",
                "Adresskarte (geplant)",
                "Ich notiere Adresslücken, weil sie zeigen, wo die Karte unvollständig wäre. Ich fülle nichts auf.",
                True,
            ),
        ],
        "dos": [
            hull,
            _step(
                2,
                "COM- oder MZ-Hinweis planen",
                "DOS-Hülle (geplant)",
                "Ein kurzer Name mit .com ist noch kein Beweis. Ich würde die Hülle nur benennen und die Probe nicht starten.",
                True,
            ),
            _step(
                3,
                "Nicht ausführen",
                "Ausführen bleibt aus",
                "Selbst mit Oversight bleibt Ausführen außerhalb dieses Stands. Ich schreibe den Plan und lege die Probe beiseite.",
                True,
            ),
        ],
        "unknown": [
            _step(
                1,
                "Hülle offen lassen",
                "Keine Zuordnung",
                "Ich erzwinge kein Format. Der Name reicht mir nicht, also bleibt die Probe bei Gelb liegen, bis du die Art angibst.",
                False,
            )
        ],
    }
    return plans.get(kind, plans["unknown"])


def detect_kind(name: str, declared: str | None) -> str:
    if declared:
        return declared if declared in KINDS else "unknown"
    lowered = name.strip().lower()
    suffix = lowered.rsplit(".", 1)[-1] if "." in lowered else ""
    if suffix == "apk" or "androidmanifest" in lowered:
        return "apk"
    if suffix in {"hex", "ihex"}:
        return "hex"
    if suffix == "com":
        return "dos"
    if any(token in lowered for token in ("mscoree", "mscorlib", "dotnet", ".net")):
        return "dotnet"
    if suffix in {"so", "elf"} or lowered.endswith(".o"):
        return "elf"
    if suffix in {"exe", "dll", "sys", "ocx"}:
        return "pe"
    return "unknown"


def classify(name: str, declared: str | None, oversight: bool) -> dict[str, Any]:
    kind = detect_kind(name, declared)
    steps = _plans(kind)
    dynamic = [step for step in steps if step["dynamic"]]
    if oversight:
        visible = steps
        withheld = False
        withheld_count = 0
        note = "Oversight ist gesetzt. Ich zeige die geplante Folge und starte sie nicht."
    else:
        visible = [step for step in steps if not step["dynamic"]]
        if not visible:
            visible = steps[:1]
        withheld = len(dynamic) > 0
        withheld_count = len(dynamic)
        note = (
            "Ohne Oversight lege ich die tieferen Schritte beiseite. "
            "Die Probe bleibt unangetastet."
            if withheld
            else "Mehr als die Hülle habe ich an diesem Namen nicht."
        )
    return {
        "queen_id": "yellow",
        "name": name.strip(),
        "kind": kind,
        "kind_label": KIND_LABEL.get(kind, kind),
        "oversight": oversight,
        "withheld": withheld,
        "withheld_count": withheld_count,
        "note": note,
        "steps": visible,
        "stub": True,
        "stub_note": "geplant/Mock",
    }
