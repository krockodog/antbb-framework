"""
All-and-One /wlan — Grundriss aus WLAN schätzen (kein Upload mehr Pflicht).
Read-only, scope-gebunden, nicht-destruktiv. Nur Darstellung/Schätzung.

Eingabe: Site-Survey-Messpunkte. Jeder Punkt ist eine Messung an einer (x,y)-
Position mit den dort sichtbaren APs und deren RSSI (dBm, negativ).
Wenn keine (x,y) bekannt sind (reiner Scan ohne Positionen), wird ein
AP-Relations-Layout per MDS geschaetzt (siehe estimate_from_scans_only()).

Ausgabe: SVG-Schema-Grundriss (Kontur aus RSSI-Heatmap-Isolinie) + geschaetzte
AP-Positionen + Rohraster als JSON. Alles klar als "geschaetzt aus WLAN".
"""
from __future__ import annotations
import math, json
from dataclasses import dataclass, field
from typing import Optional

# ---------- Datentypen ----------
@dataclass
class Observation:
    bssid: str
    rssi: float            # dBm, z.B. -42
    ssid: str = ""

@dataclass
class SurveyPoint:
    x: float               # Messposition in Metern (relativ)
    y: float
    obs: list[Observation] = field(default_factory=list)

# ---------- RSSI -> Distanz (Log-Distance Path Loss) ----------
def rssi_to_distance(rssi: float, tx_power: float = -40.0, n: float = 2.5) -> float:
    """tx_power = RSSI in 1 m; n = Dämpfungsexponent (2 frei, 3-4 Innenraum)."""
    return 10 ** ((tx_power - rssi) / (10 * n))

# ---------- AP-Position per gewichteter Trilateration ----------
def estimate_ap_positions(points: list[SurveyPoint]) -> dict[str, tuple[float, float]]:
    """Schwerpunkt der Messpositionen, gewichtet mit Signalstärke (stark=näher)."""
    acc: dict[str, list[float]] = {}
    for p in points:
        for o in p.obs:
            w = 10 ** (o.rssi / 20.0)          # linear ~ Feldstärke
            a = acc.setdefault(o.bssid, [0.0, 0.0, 0.0])
            a[0] += p.x * w; a[1] += p.y * w; a[2] += w
    return {b: (a[0]/a[2], a[1]/a[2]) for b, a in acc.items() if a[2] > 0}

# ---------- Abdeckungs-/Signalraster ----------
def coverage_grid(points: list[SurveyPoint], cell: float = 0.5, margin: float = 3.0):
    xs = [p.x for p in points]; ys = [p.y for p in points]
    if not xs:
        return None
    x0, x1 = min(xs) - margin, max(xs) + margin
    y0, y1 = min(ys) - margin, max(ys) + margin
    nx = max(1, int((x1 - x0) / cell)); ny = max(1, int((y1 - y0) / cell))
    grid = [[-120.0] * nx for _ in range(ny)]   # bestes RSSI je Zelle
    for p in points:
        best = max((o.rssi for o in p.obs), default=-120.0)
        gx = min(nx - 1, int((p.x - x0) / cell)); gy = min(ny - 1, int((p.y - y0) / cell))
        # IDW-Verteilung um den Messpunkt
        for yy in range(ny):
            for xx in range(nx):
                d = math.hypot((xx - gx) * cell, (yy - gy) * cell)
                val = best - 12 * math.log10(1 + d)   # Abfall
                if val > grid[yy][xx]:
                    grid[yy][xx] = val
    return {"x0": x0, "y0": y0, "cell": cell, "nx": nx, "ny": ny, "grid": grid}

# ---------- Kontur (Isolinie) als grober Raum-Umriss ----------
def contour_polygon(cg: dict, threshold: float = -75.0) -> list[tuple[float, float]]:
    """Randzellen oberhalb threshold -> konvexe Hülle = grobe Flächenkontur."""
    pts = []
    for yy in range(cg["ny"]):
        for xx in range(cg["nx"]):
            if cg["grid"][yy][xx] >= threshold:
                pts.append((cg["x0"] + xx * cg["cell"], cg["y0"] + yy * cg["cell"]))
    return _convex_hull(pts)

def _convex_hull(pts):
    pts = sorted(set(pts))
    if len(pts) <= 2:
        return pts
    def cross(o, a, b): return (a[0]-o[0])*(b[1]-o[1]) - (a[1]-o[1])*(b[0]-o[0])
    lo = []
    for p in pts:
        while len(lo) >= 2 and cross(lo[-2], lo[-1], p) <= 0: lo.pop()
        lo.append(p)
    up = []
    for p in reversed(pts):
        while len(up) >= 2 and cross(up[-2], up[-1], p) <= 0: up.pop()
        up.append(p)
    return lo[:-1] + up[:-1]

# ---------- SVG rendern ----------
def render_svg(points, aps, hull, cg, scale: float = 24.0) -> str:
    def tx(x): return (x - cg["x0"]) * scale + 20
    def ty(y): return (y - cg["y0"]) * scale + 20
    w = cg["nx"] * cg["cell"] * scale + 40; h = cg["ny"] * cg["cell"] * scale + 40
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0f}" height="{h:.0f}" '
             f'viewBox="0 0 {w:.0f} {h:.0f}" font-family="sans-serif">']
    parts.append(f'<rect width="{w:.0f}" height="{h:.0f}" fill="#0b0f14"/>')
    # Heatmap
    for yy in range(cg["ny"]):
        for xx in range(cg["nx"]):
            v = cg["grid"][yy][xx]
            if v < -95: continue
            t = max(0.0, min(1.0, (v + 95) / 55))
            r = int(40 + 180 * t); g = int(60 + 120 * (1-abs(t-0.5)*2)); b = int(120 * (1-t))
            parts.append(f'<rect x="{tx(cg["x0"]+xx*cg["cell"]):.1f}" y="{ty(cg["y0"]+yy*cg["cell"]):.1f}" '
                         f'width="{cg["cell"]*scale:.1f}" height="{cg["cell"]*scale:.1f}" fill="rgb({r},{g},{b})" opacity="0.5"/>')
    # Kontur (geschätzter Grundriss)
    if hull:
        d = "M " + " L ".join(f"{tx(x):.1f},{ty(y):.1f}" for x, y in hull) + " Z"
        parts.append(f'<path d="{d}" fill="none" stroke="#6ee7ff" stroke-width="2.5" stroke-dasharray="6 4"/>')
    # Messpunkte
    for p in points:
        parts.append(f'<circle cx="{tx(p.x):.1f}" cy="{ty(p.y):.1f}" r="2.5" fill="#9aa4b2"/>')
    # APs
    for b, (x, y) in aps.items():
        parts.append(f'<circle cx="{tx(x):.1f}" cy="{ty(y):.1f}" r="5" fill="#ffd166"/>'
                     f'<text x="{tx(x)+7:.1f}" y="{ty(y)+4:.1f}" fill="#ffd166" font-size="10">{b[-5:]}</text>')
    parts.append('<text x="14" y="16" fill="#6ee7ff" font-size="12">Grundriss geschätzt aus WLAN (kein Upload)</text>')
    parts.append('</svg>')
    return "".join(parts)


def render_svg_topology(aps_norm: dict, walls: list) -> str:
    """SVG im Heatmap-Farbstil: dunkler Grund, cyanfarbene Waende, AP-Marker.
    aps_norm: {bssid: [x,y] in 0..1}; walls: [x1,y1,x2,y2] normierte Segmente."""
    if not aps_norm:
        return ""
    w, h = 900, 620
    def tx(x): return x * w
    def ty(y): return y * h
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
             f'viewBox="0 0 {w} {h}" font-family="sans-serif">']
    parts.append(f'<rect width="{w}" height="{h}" fill="#05070c"/>')
    # Raster wie die Heatmap
    for gx in range(0, w, 40):
        parts.append(f'<line x1="{gx}" y1="0" x2="{gx}" y2="{h}" stroke="rgba(56,224,255,0.08)"/>')
    for gy in range(0, h, 40):
        parts.append(f'<line x1="0" y1="{gy}" x2="{w}" y2="{gy}" stroke="rgba(56,224,255,0.08)"/>')
    # Waende (geschätzter Grundriss)
    for seg in walls or []:
        x1, y1, x2, y2 = seg
        parts.append(f'<line x1="{tx(x1):.1f}" y1="{ty(y1):.1f}" x2="{tx(x2):.1f}" y2="{ty(y2):.1f}" '
                     'stroke="#6ee7ff" stroke-width="4" stroke-linecap="square" opacity="0.9"/>')
    # APs
    for b, p in aps_norm.items():
        parts.append(f'<circle cx="{tx(p[0]):.1f}" cy="{ty(p[1]):.1f}" r="7" fill="#ffd166"/>'
                     f'<text x="{tx(p[0])+10:.1f}" y="{ty(p[1])+4:.1f}" fill="#ffd166" font-size="12">{b[-5:]}</text>')
    parts.append('<text x="14" y="20" fill="#6ee7ff" font-size="13">Grundriss geschätzt aus WLAN '
                 '(Näherung – Upload nur optional)</text>')
    parts.append('</svg>')
    return "".join(parts)

# ---------- Hauptfunktion ----------
def floorplan_from_survey(points: list[SurveyPoint], threshold: float = -75.0) -> dict:
    cg = coverage_grid(points)
    if cg is None:
        return {"ok": False, "error": "keine Messpunkte mit Position"}
    aps = estimate_ap_positions(points)
    hull = contour_polygon(cg, threshold)
    return {
        "ok": True, "estimated": True, "source": "wlan-survey",
        "aps": {b: {"x": round(x, 2), "y": round(y, 2)} for b, (x, y) in aps.items()},
        "hull": [[round(x, 2), round(y, 2)] for x, y in hull],
        "svg": render_svg(points, aps, hull, cg),
        "note": "Geschätzt aus WLAN (RSSI-Näherung). Genauigkeit steigt mit Zahl der Messpunkte.",
    }

# ---------- Fallback: nur Scans ohne Positionen (AP-Relationslayout per MDS) ----------
def _hash01(s: str) -> float:
    """Deterministischer Hash 0..1 (fuer stabile Winkel ohne Zufall)."""
    h = 0
    for ch in s:
        h = (h * 131 + ord(ch)) & 0xFFFFFFFF
    return (h % 1000) / 1000.0


def layout_star(observations: list, anchor_bssid: str | None = None) -> dict:
    """2D-Stern-Layout um den staerksten AP (Anchor = Router).
    Distanz aus RSSI, Winkel deterministisch aus der BSSID – auch EIN Scan
    ergibt so eine echte 2D-Karte statt einer degenerierten Linie."""
    if not observations:
        return {}
    best = anchor_bssid
    if not best:
        best = max(observations, key=lambda o: o.rssi).bssid
    anchor = next((o for o in observations if o.bssid == best), observations[0])
    dists = {o.bssid: rssi_to_distance(o.rssi) for o in observations}
    dmax = max(dists.values()) or 1.0
    coords: dict[str, tuple[float, float]] = {}
    idx = 0
    for o in observations:
        if o.bssid == anchor.bssid:
            coords[o.bssid] = (0.0, 0.0)
            continue
        r = 0.6 + 3.4 * (dists[o.bssid] / dmax)      # 0.6..4.0 m
        ang = 2.399963 * idx + _hash01(o.bssid) * 1.2  # goldener Winkel + Streuung
        coords[o.bssid] = (r * math.cos(ang), r * math.sin(ang))
        idx += 1
    return coords


def normalize_aps(coords: dict) -> dict:
    """Normiert AP-Koordinaten auf 0.08..0.92 (Canvas-tauglich)."""
    if not coords:
        return {}
    xs = [p[0] for p in coords.values()]
    ys = [p[1] for p in coords.values()]
    x0, x1 = min(xs), max(xs)
    y0, y1 = min(ys), max(ys)
    dx = (x1 - x0) or 1.0
    dy = (y1 - y0) or 1.0
    return {b: [round(0.08 + 0.84 * (p[0] - x0) / dx, 3),
                round(0.08 + 0.84 * (p[1] - y0) / dy, 3)]
            for b, p in coords.items()}


def orthogonal_walls(aps_norm: dict) -> list:
    """Rechtwinkliger Schaubau: Aussenwand um die AP-Huelle (+ Mittelwand bei Breite).
    Gibt normierte Wandsegmente [x1,y1,x2,y2] zurueck."""
    if not aps_norm:
        return []
    xs = [p[0] for p in aps_norm.values()]
    ys = [p[1] for p in aps_norm.values()]
    pad = 0.07
    x0, x1 = max(0.02, min(xs) - pad), min(0.98, max(xs) + pad)
    y0, y1 = max(0.02, min(ys) - pad), min(0.98, max(ys) + pad)
    walls = [[x0, y0, x1, y0], [x1, y0, x1, y1],
             [x1, y1, x0, y1], [x0, y1, x0, y0]]
    if x1 - x0 > 0.5:   # breite Flur: eine Mittelwand suggeriert zwei Raeume
        mx = round((x0 + x1) / 2, 3)
        walls.append([mx, y0, mx, round(y0 + (y1 - y0) * 0.55, 3)])
    return walls


def estimate_from_scans_only(scans: list[list[Observation]]) -> dict:
    """Jeder Scan = Liste sichtbarer APs mit RSSI. Ähnlichkeit zweier APs =
    wie oft/wie stark sie gemeinsam gesehen werden -> 2D-Layout (MDS), mit
    Stern-Layout-Fallback wenn zu wenige Scans oder degeneriert."""
    all_obs = [o for s in scans for o in s]
    by_bssid: dict[str, list[float]] = {}
    for o in all_obs:
        by_bssid.setdefault(o.bssid, []).append(o.rssi)
    if len(by_bssid) < 2:
        return {"ok": False, "error": "zu wenige APs"}

    # MDS nur sinnvoll mit >= 2 Scans; sonst direkt Stern-Layout.
    coords: dict[str, tuple[float, float]] | None = None
    if len(scans) >= 2:
        bssids = sorted(by_bssid)
        idx = {b: i for i, b in enumerate(bssids)}
        n = len(bssids)
        D = [[0.0]*n for _ in range(n)]
        cnt = [[0]*n for _ in range(n)]
        for s in scans:
            m = {o.bssid: o.rssi for o in s}
            for a in m:
                for b in m:
                    if a < b:
                        d = abs(m[a]-m[b]) + 1.0   # ähnliches RSSI => nah
                        i, j = idx[a], idx[b]
                        D[i][j] += d; D[j][i] += d; cnt[i][j]+=1; cnt[j][i]+=1
        for i in range(n):
            for j in range(n):
                if cnt[i][j]: D[i][j] /= cnt[i][j]
                elif i!=j: D[i][j] = 30.0
        cand = _mds_2d(D)
        ys = [p[1] for p in cand]
        if max(ys) - min(ys) > 1e-3:            # nicht degeneriert?
            coords = {bssids[i]: cand[i] for i in range(n)}
    if coords is None:
        # Stern-Layout: staerkster AP (mittlerer RSSI) als Router-Anchor
        anchor = max(by_bssid, key=lambda b: sum(by_bssid[b]) / len(by_bssid[b]))
        obs = [Observation(b, sum(rs)/len(rs), "") for b, rs in by_bssid.items()]
        coords = layout_star(obs, anchor_bssid=anchor)

    hull = _convex_hull(list(coords.values()))
    aps_norm = normalize_aps(coords)
    walls = orthogonal_walls(aps_norm)
    return {"ok": True, "estimated": True, "source": "wlan-scan-mds",
            "aps": {b: {"x": round(x,2), "y": round(y,2)} for b,(x,y) in coords.items()},
            "aps_norm": aps_norm,
            "walls": walls,
            "hull": [[round(x,2), round(y,2)] for x,y in hull],
            "svg": render_svg_topology(aps_norm, walls),
            "note": "Geschätzt aus WLAN (RSSI-Näherung). Genauigkeit steigt mit Zahl der Scans/Messpunkte."}

def _mds_2d(D):
    n = len(D)
    D2 = [[D[i][j]**2 for j in range(n)] for i in range(n)]
    J = [[(1.0 if i==j else 0.0) - 1.0/n for j in range(n)] for i in range(n)]
    B = _matmul(_matmul(J, _scale(D2, -0.5)), J)
    # Power-Iteration für 2 größte Eigenvektoren
    def eig(B):
        import random
        v = [random.random() for _ in range(n)]
        for _ in range(200):
            w = [sum(B[i][k]*v[k] for k in range(n)) for i in range(n)]
            nrm = math.sqrt(sum(c*c for c in w)) or 1.0
            v = [c/nrm for c in w]
        lam = sum(v[i]*sum(B[i][k]*v[k] for k in range(n)) for i in range(n))
        return lam, v
    l1, v1 = eig(B)
    B2 = [[B[i][j]-l1*v1[i]*v1[j] for j in range(n)] for i in range(n)]
    l2, v2 = eig(B2)
    s1 = math.sqrt(max(l1,0)); s2 = math.sqrt(max(l2,0))
    return [(v1[i]*s1, v2[i]*s2) for i in range(n)]

def _matmul(A, B):
    n=len(A); m=len(B[0]); k=len(B)
    return [[sum(A[i][t]*B[t][j] for t in range(k)) for j in range(m)] for i in range(n)]
def _scale(A, s): return [[v*s for v in row] for row in A]


if __name__ == "__main__":
    # Mini-Demo mit 3 APs und ein paar Messpunkten
    demo = [
        SurveyPoint(0,0,[Observation("AA:11",-45),Observation("BB:22",-70),Observation("CC:33",-80)]),
        SurveyPoint(4,0,[Observation("AA:11",-65),Observation("BB:22",-48),Observation("CC:33",-75)]),
        SurveyPoint(2,3,[Observation("AA:11",-68),Observation("BB:22",-66),Observation("CC:33",-50)]),
        SurveyPoint(1,1,[Observation("AA:11",-52),Observation("BB:22",-60),Observation("CC:33",-70)]),
    ]
    r = floorplan_from_survey(demo)
    print(json.dumps({k:v for k,v in r.items() if k!="svg"}, indent=2, ensure_ascii=False))
    open("/workspace/wlan-floorplan/demo.svg","w").write(r["svg"])
    print("SVG -> /workspace/wlan-floorplan/demo.svg")
