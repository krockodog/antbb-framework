// antbb Stadtausbau (Siedler/Anno-Stil) – Stufe 4 + 5 als Erweiterungsring um die Metropole.
// Nur echte Daten: die Stufe kommt per postMessage vom /brain-Elternfenster (Wissen aus
// /api/brain/nodes). Kein Default-Fake. Vorschau-Stufen setzt nur das Elternfenster (Admin).
// Performance: alles InstancedMesh (wenige Draw-Calls), Ameisen-Update gedrosselt, keine
// Dauerrotation von Koenigin/Thron. Rot (Zentrum), Blau (links), Gelb (rechts) bleiben unberuehrt.
(function () {
  "use strict";
  const TAU = Math.PI * 2;
  let built = 0, C = null, root = null, groups = {}, antSets = [], raf = 0, pending = 0;

  function rng(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296); }
  const P = (r, a, y) => [Math.sin(a) * r, y, Math.cos(a) * r];
  // radiale Strassen/Machtadern liegen auf k*PI/4, Wurzel-Kraken auf k*TAU/22 -> freihalten
  const nearRoad = (a, w) => { const d = ((a % (Math.PI / 4)) + Math.PI / 4) % (Math.PI / 4); return d < w || d > Math.PI / 4 - w; };
  const nearRoot = (a, w) => { const s = TAU / 22, d = ((a % s) + s) % s; return d < w || d > s - w; };

  function ready() { return window.__CITY__ && window.__SCENE_READY__; }

  function inst(name, geo, mat, list, opts = {}) {
    const T = C.T, n = list.length; if (!n) return null;
    const m = new T.Inst(geo, mat, n); m.name = name;
    const M = new T.Mat4(), q = new T.Quat(), v = new T.V3(), s = new T.V3(), up = new T.V3(0, 1, 0);
    list.forEach((it, i) => {
      v.set(it.p[0], it.p[1], it.p[2]); q.setFromAxisAngle(up, it.rot || 0);
      const sc = it.s || [1, 1, 1]; s.set(sc[0], sc[1], sc[2]);
      M.compose(v, q, s); m.setMatrixAt(i, M);
      if (it.c != null && m.setColorAt) m.setColorAt(i, new T.Color(it.c));
    });
    m.instanceMatrix.needsUpdate = true; if (m.instanceColor) m.instanceColor.needsUpdate = true;
    m.castShadow = false; m.receiveShadow = !!opts.receive;
    return m;
  }
  function mats() {
    const T = C.T;
    return {
      plate: new T.Std({ color: 0x7d5a38, roughness: .95 }),
      plate2: new T.Std({ color: 0x86613c, roughness: .93 }),
      stone: new T.Std({ color: 0xc2a77c, roughness: .85 }),
      wall: new T.Std({ color: 0xcfb58a, roughness: .8 }),
      wood: new T.Std({ color: 0x7a5232, roughness: .9 }),
      roof: new T.Std({ color: 0xb6553a, roughness: .75 }),
      roof2: new T.Std({ color: 0x8e3f2c, roughness: .78 }),
      leaf: new T.Std({ color: 0x4f8a3c, roughness: .9 }),
      leaf2: new T.Std({ color: 0x356b33, roughness: .9 }),
      lawn: new T.Std({ color: 0x5d8f45, roughness: .95 }),
      water: new T.Std({ color: 0x0b86a8, roughness: .18, metalness: .25, emissive: 0x0a5a73, emissiveIntensity: .9, transparent: true, opacity: .92 }),
      gold: new T.Std({ color: 0xe0b45a, roughness: .28, metalness: .9, emissive: 0x4a3008, emissiveIntensity: .6 }),
      crystal: new T.Std({ color: 0x9ff3ff, roughness: .1, metalness: .2, emissive: 0x38e0ff, emissiveIntensity: 1.4, transparent: true, opacity: .9 }),
      lamp: new T.Basic({ color: 0xffd98a }),
      awning: new T.Std({ color: 0xffffff, roughness: .7 }),
      banner: new T.Std({ color: 0xffffff, roughness: .6, side: 2 }),
      smoke: new T.Std({ color: 0x5a5048, roughness: 1 }),
    };
  }

  // ---------- Stufe 4: wachsende Kleinstadt (Vorstadtring r 17.6–20.6) ----------
  function buildStage4() {
    const T = C.T, M = mats(), g = new T.Group(); g.name = "AUSBAU_STUFE_4_KLEINSTADT";
    const R = rng(4004), Y = -1.17;
    const plate = new T.Mesh(new T.Cyl(20.8, 21.1, .12, 128), M.plate); plate.position.y = Y - .06; plate.name = "VORSTADT_TERRASSE"; g.add(plate);
    const road = new T.Mesh(new T.Torus(19.1, .2, 3, 160), M.stone); road.rotation.x = Math.PI / 2; road.scale.z = .25; road.position.y = Y + .01; road.name = "RINGSTRASSE_VORSTADT"; g.add(road);
    // Teiche + kurze Kanalbögen
    const ponds = [], canal = [];
    for (let k = 0; k < 6; k++) { const a = k * TAU / 6 + .26; ponds.push({ p: P(20.0, a, Y + .02), s: [1, 1, 1], a }); }
    g.add(inst("TEICHE", new T.Cyl(.7, .7, .05, 28), M.water, ponds));
    g.add(inst("TEICH_UFER", new T.Torus(.72, .06, 4, 28).rotateX(Math.PI / 2), M.stone, ponds.map(o => ({ p: [o.p[0], Y + .04, o.p[2]] }))));
    for (let k = 0; k < 4; k++) { const a0 = k * TAU / 4 + .62; for (let i = 0; i < 9; i++) { const a = a0 + i * .035; canal.push({ p: P(17.85, a, Y + .015), rot: a + Math.PI / 2, s: [1, 1, 1] }); } }
    g.add(inst("KANAL_SEGMENTE", new T.Box(.7, .04, .32), M.water, canal));
    // Marktplätze (4)
    const plaza = [], stalls = [], aw = [];
    for (let k = 0; k < 4; k++) {
      const a = k * TAU / 4 + Math.PI / 8 + .02, c = P(19.3, a, Y + .02); plaza.push({ p: c });
      for (let j = 0; j < 6; j++) { const b = j * TAU / 6, x = c[0] + Math.cos(b) * .62, z = c[2] + Math.sin(b) * .62;
        stalls.push({ p: [x, Y + .12, z], rot: -b }); aw.push({ p: [x, Y + .27, z], rot: -b, c: [0xd94b3d, 0xf0c24a, 0x3b8bff, 0x4fae5b, 0xe58a3a, 0xc04fd6][j] }); }
    }
    g.add(inst("MARKTPLAETZE", new T.Cyl(.95, .95, .04, 24), M.stone, plaza));
    g.add(inst("MARKTSTAENDE", new T.Box(.22, .2, .16), M.wood, stalls));
    g.add(inst("MARKT_MARKISEN", new T.Cone(.17, .1, 4), M.awning, aw));
    // Werkstätten / Handwerkerhäuser
    const body = [], roofs = [], chim = [], smoke = [];
    for (let i = 0; i < 52; i++) {
      const a = R() * TAU; if (nearRoad(a, .07) || nearRoot(a, .06)) { i--; continue; }
      const r = (i % 2 ? 18.3 : 19.95) + (R() - .5) * .35;
      const near = plaza.some(q => Math.hypot(q.p[0] - Math.sin(a) * r, q.p[2] - Math.cos(a) * r) < 1.25) || ponds.some(q => Math.hypot(q.p[0] - Math.sin(a) * r, q.p[2] - Math.cos(a) * r) < 1.0);
      if (near) { i--; continue; }
      const w = .5 + R() * .25, h = .42 + R() * .3, p = P(r, a, Y + h / 2);
      body.push({ p, rot: a, s: [w, h, w * .8] });
      roofs.push({ p: [p[0], Y + h + .15, p[2]], rot: a + Math.PI / 4, s: [w * .8, .3, w * .8], c: i % 3 ? 0xb6553a : 0x8e3f2c });
      if (i % 2 === 0) { chim.push({ p: [p[0] + .12, Y + h + .2, p[2]], s: [1.5, 1.6, 1.5] }); smoke.push({ p: [p[0] + .12, Y + h + .48, p[2]], s: [1.8, 1.8, 1.8] }); }
    }
    g.add(inst("WERKSTAETTEN", new T.Box(1, 1, 1), M.wall, body));
    g.add(inst("WERKSTATT_DAECHER", new T.Cone(.72, 1, 4), M.roof, roofs));
    g.add(inst("SCHORNSTEINE", new T.Cyl(.035, .035, .16, 6), M.stone, chim));
    g.add(inst("RAUCH", new T.Ico(.05, 0), M.smoke, smoke));
    // Gärten + Bäume
    const trunks = [], crowns = [], beds = [];
    for (let i = 0; i < 90; i++) {
      const a = R() * TAU; if (nearRoad(a, .05)) { i--; continue; }
      const r = 17.75 + R() * 2.85, sc = 1.1 + R() * .8, p = P(r, a, Y);
      trunks.push({ p: [p[0], Y + .12 * sc, p[2]], s: [sc, sc, sc] });
      crowns.push({ p: [p[0], Y + .32 * sc, p[2]], s: [sc, sc * 1.1, sc], c: i % 3 ? 0x4f8a3c : 0x356b33 });
    }
    for (let i = 0; i < 24; i++) { const a = i * TAU / 24 + .13; beds.push({ p: P(20.45, a, Y + .02), rot: a, s: [1, 1, 1] }); }
    g.add(inst("BAUMSTAEMME", new T.Cyl(.025, .035, .24, 5), M.wood, trunks));
    g.add(inst("BAUMKRONEN", new T.Ico(.14, 0), M.leaf, crowns));
    g.add(inst("GAERTEN", new T.Box(.5, .04, .28), M.lawn, beds));
    root.add(g); groups[4] = g;
    // Bewohner: echte Arbeiter-Miniatur der Stadt (Instancing) auf der Ringstrasse
    addAnts("BEWOHNER_STUFE_4", C.ants.worker, 180, [[19.1, .25], [18.0, .18]], Y + .02, 41);
    addAnts("HANDWERKER_STUFE_4", C.ants.forgeWorker, 40, [[19.55, .2]], Y + .02, 42);
  }

  // ---------- Stufe 5: volle Stadt (Außenring r 20.6–23.6 + Reichtum) ----------
  function buildStage5() {
    const T = C.T, M = mats(), g = new T.Group(); g.name = "AUSBAU_STUFE_5_METROPOLE";
    const R = rng(5005), Y = -1.17;
    const plate = new T.Mesh(new T.Cyl(23.7, 24.0, .1, 160), M.plate2); plate.position.y = Y - .08; plate.name = "AUSSENRING_TERRASSE"; g.add(plate);
    const canal = new T.Mesh(new T.Torus(20.95, .3, 3, 180), M.water); canal.rotation.x = Math.PI / 2; canal.scale.z = .12; canal.position.y = Y + .015; canal.name = "AUSSENKANAL"; g.add(canal);
    const road = new T.Mesh(new T.Torus(22.2, .18, 3, 180), M.stone); road.rotation.x = Math.PI / 2; road.scale.z = .25; road.position.y = Y + .01; road.name = "RINGSTRASSE_AUSSEN"; g.add(road);
    // Brücken über den Außenkanal auf den 8 Hauptachsen
    const decks = [], rails = [];
    for (let k = 0; k < 8; k++) { const a = k * Math.PI / 4; decks.push({ p: P(20.95, a, Y + .07), rot: a, s: [1, 1, 1] });
      for (const off of [-.2, .2]) { const p = P(20.95, a, Y + .14); rails.push({ p: [p[0] + Math.cos(a) * off, p[1], p[2] - Math.sin(a) * off], rot: a }); } }
    g.add(inst("BRUECKEN", new T.Box(.5, .07, .95), M.stone, decks));
    g.add(inst("BRUECKEN_GELAENDER", new T.Box(.04, .1, .95), M.gold, rails));
    // Paläste / Bibliothek / Akademie (4 Monumentalbauten)
    const pb = [], cols = [], domes = [], spires = [];
    for (let k = 0; k < 4; k++) {
      const a = k * TAU / 4 + Math.PI / 4 + Math.PI / 8, c = P(22.75, a, Y);
      pb.push({ p: [c[0], Y + .5, c[2]], rot: a, s: [2.1, 1.0, 1.4] });
      for (let j = 0; j < 6; j++) { const t = (j / 5 - .5) * 1.8; cols.push({ p: [c[0] + Math.cos(a) * t - Math.sin(a) * .8, Y + .5, c[2] - Math.sin(a) * t - Math.cos(a) * .8], s: [1.4, 1.6, 1.4] }); }
      domes.push({ p: [c[0], Y + 1.0, c[2]], s: [1.6, 1.4, 1.6] });
      spires.push({ p: [c[0], Y + 1.85, c[2]], s: [1.6, 2.2, 1.6] });
    }
    g.add(inst("PALAST_AKADEMIE_BIBLIOTHEK", new T.Box(1, 1, 1), M.wall, pb));
    g.add(inst("SAEULEN", new T.Cyl(.035, .035, .62, 8), M.stone, cols));
    g.add(inst("KUPPELN_GOLD", new T.Sphere(.42, 20, 12, 0, TAU, 0, Math.PI / 2), M.gold, domes));
    g.add(inst("WISSENS_KRISTALLE", new T.Oct(.13, 0), M.crystal, spires));
    // Türme
    const tw = [], tr = [], tc = [];
    for (let k = 0; k < 16; k++) {
      const a = k * TAU / 16 + .2; if (nearRoad(a, .06)) continue;
      const h = 1.9 + (k % 3) * .6, p = P(k % 2 ? 23.2 : 21.6, a, Y);
      tw.push({ p: [p[0], Y + h / 2, p[2]], s: [1.4, h, 1.4] });
      tr.push({ p: [p[0], Y + h + .25, p[2]], s: [1.4, 1.4, 1.4], c: k % 2 ? 0xb6553a : 0xe0b45a });
      tc.push({ p: [p[0], Y + h + .7, p[2]], s: [1.8, 2.4, 1.8] });
    }
    g.add(inst("TUERME", new T.Cyl(.16, .2, 1, 10), M.stone, tw));
    g.add(inst("TURMDAECHER", new T.Cone(.24, .36, 10), M.roof, tr));
    g.add(inst("TURM_KRISTALLE", new T.Oct(.07, 0), M.crystal, tc));
    // Bürgerhäuser Außenring
    const hb = [], hr = [];
    for (let i = 0; i < 70; i++) {
      const a = R() * TAU; if (nearRoad(a, .05)) { i--; continue; }
      const r = 21.5 + R() * 1.9;
      if (pb.some(q => Math.hypot(q.p[0] - Math.sin(a) * r, q.p[2] - Math.cos(a) * r) < 1.3)) { i--; continue; }
      const w = .45 + R() * .22, h = .5 + R() * .55, p = P(r, a, Y + h / 2);
      hb.push({ p, rot: a, s: [w, h, w] }); hr.push({ p: [p[0], Y + h + .08, p[2]], rot: a, s: [w * 1.1, .16, w * 1.1], c: i % 4 ? 0xb6553a : 0xe0b45a });
    }
    g.add(inst("BUERGERHAEUSER", new T.Box(1, 1, 1), M.wall, hb));
    g.add(inst("BUERGERDAECHER", new T.Box(1, 1, 1), M.roof2, hr));
    // Parks + viel Grün
    const lawns = [], trunks = [], crowns = [];
    for (let k = 0; k < 8; k++) { const a = k * TAU / 8 + .32; lawns.push({ p: P(22.5, a, Y + .015), rot: a }); }
    for (let i = 0; i < 160; i++) {
      const a = R() * TAU, r = 20.7 + R() * 3.0; if (nearRoad(a, .04)) { i--; continue; }
      const sc = 1.1 + R() * .9, p = P(r, a, Y);
      trunks.push({ p: [p[0], Y + .12 * sc, p[2]], s: [sc, sc, sc] }); crowns.push({ p: [p[0], Y + .32 * sc, p[2]], s: [sc, sc * 1.15, sc], c: i % 2 ? 0x4f8a3c : 0x2f6b3a });
    }
    g.add(inst("PARKS", new T.Cyl(.9, .9, .03, 20), M.lawn, lawns));
    g.add(inst("PARK_STAEMME", new T.Cyl(.025, .035, .24, 5), M.wood, trunks));
    g.add(inst("PARK_KRONEN", new T.Ico(.15, 0), M.leaf2, crowns));
    // Wasseroasen / Brunnenanlagen
    const basins = [], wat = [], jets = [];
    for (let k = 0; k < 8; k++) { const a = k * TAU / 8 + .32, p = P(22.5, a, Y); basins.push({ p: [p[0], Y + .06, p[2]] }); wat.push({ p: [p[0], Y + .1, p[2]] }); jets.push({ p: [p[0], Y + .3, p[2]] }); }
    g.add(inst("OASEN_BECKEN", new T.Cyl(.42, .46, .1, 20), M.stone, basins));
    g.add(inst("OASEN_WASSER", new T.Cyl(.37, .37, .03, 20), M.water, wat));
    g.add(inst("FONTAENEN", new T.Ico(.09, 1), M.crystal, jets));
    // Reichtum: Gold-Akzente, Banner, Beleuchtung
    const lamps = [], poles = [], flags = [];
    for (let i = 0; i < 96; i++) { const a = i * TAU / 96; const p = P(i % 2 ? 22.45 : 19.45, a, Y); poles.push({ p: [p[0], Y + .2, p[2]] }); lamps.push({ p: [p[0], Y + .42, p[2]] }); }
    const BC = [0xd93a3a, 0x3b8bff, 0xf2c23c];
    for (let i = 0; i < 24; i++) { const a = i * TAU / 24 + .09, p = P(23.45, a, Y);
      // Bannerfarbe nach Sektor: links Blau, rechts Gelb, sonst Rot (Rot = Herrscherin)
      const sx = Math.sin(a), col = sx < -.55 ? BC[1] : (sx > .55 ? BC[2] : BC[0]);
      flags.push({ p: [p[0], Y + .78, p[2]], rot: a, c: col }); poles.push({ p: [p[0], Y + .45, p[2]], s: [1, 2.3, 1] }); }
    g.add(inst("LATERNENMASTEN", new T.Cyl(.015, .015, .4, 5), M.wood, poles));
    g.add(inst("LATERNEN", new T.Sphere(.045, 8, 6), M.lamp, lamps));
    g.add(inst("BANNER", new T.Plane(.18, .3), M.banner, flags));
    // Beleuchtung bewusst nur emissiv (keine zusätzlichen PointLights → kein Shader-Mehraufwand auf schwachen GPUs)
    root.add(g); groups[5] = g;
    addAnts("BEVOELKERUNG_STUFE_5", C.ants.worker, 520, [[22.2, .3], [20.4, .2], [23.2, .22], [18.6, .2]], Y + .02, 51);
    addAnts("RE_HANDWERKER_STUFE_5", C.ants.forgeWorker, 80, [[22.2, .26]], Y + .02, 52);
    addAnts("REKRUTEN_STUFE_5", C.ants.trainee, 60, [[20.4, .22]], Y + .02, 53);
  }

  function addAnts(name, model, n, lanes, y, seed) {
    if (!model || !model.geometry) return;
    const T = C.T, R = rng(seed), m = new T.Inst(model.geometry, model.material, n); m.name = name;
    m.frustumCulled = false;
    const a = new Float32Array(n), sp = new Float32Array(n), rr = new Float32Array(n);
    for (let i = 0; i < n; i++) { const L = lanes[i % lanes.length]; a[i] = R() * TAU; sp[i] = (.018 + R() * .03) * (R() < .5 ? 1 : -1); rr[i] = L[0] + (R() - .5) * 2 * L[1]; }
    const set = { m, a, sp, rr, y, M: new T.Mat4(), q: new T.Quat(), v: new T.V3(), s: new T.V3(1, 1, 1), up: new T.V3(0, 1, 0) };
    antSets.push(set); stepAnts(set, 0); root.add(m);
  }
  function stepAnts(set, dt) {
    const { m, a, sp, rr, y, M, q, v, s, up } = set;
    for (let i = 0; i < a.length; i++) {
      a[i] += sp[i] * dt; const r = rr[i];
      v.set(Math.sin(a[i]) * r, y, Math.cos(a[i]) * r);
      q.setFromAxisAngle(up, a[i] + (sp[i] > 0 ? Math.PI / 2 : -Math.PI / 2)); M.compose(v, q, s); m.setMatrixAt(i, M);
    }
    m.instanceMatrix.needsUpdate = true;
  }
  let last = 0, acc = 0;
  function loop(now) {
    raf = requestAnimationFrame(loop);
    const dt = last ? Math.min(.1, (now - last) / 1000) : 0; last = now; acc += dt;
    if (acc < 1 / 30) return; // gedrosselt (schwache Rechner)
    if (document.hidden) { acc = 0; return; }
    for (const s of antSets) stepAnts(s, acc);
    acc = 0;
  }

  function apply(stage) {
    stage = Math.max(0, Math.min(5, stage | 0));
    if (!ready()) { pending = stage; return; }
    C = window.__CITY__; root = C.root;
    if (stage >= 4 && built < 4) { buildStage4(); built = 4; }
    if (stage >= 5 && built < 5) { buildStage5(); built = 5; }
    if (groups[4]) groups[4].visible = stage >= 4;
    if (groups[5]) groups[5].visible = stage >= 5;
    for (const s of antSets) s.m.visible = s.m.name.endsWith("_4") ? stage >= 4 : stage >= 5;
    if (antSets.length && !raf) raf = requestAnimationFrame(loop);
    window.__GROWTH_STATE__ = { stage, built, ants: antSets.reduce((t, s) => t + (s.m.visible ? s.m.count : 0), 0) };
  }
  window.__GROWTH__ = { apply };
  addEventListener("message", (ev) => {
    if (ev.origin !== location.origin || ev.source !== parent) return;
    const d = ev.data; if (!d || d.type !== "antbb-knowledge") return;
    apply(Number(d.stage) || 0);
  });
  const t = setInterval(() => { if (ready()) { clearInterval(t); if (pending) apply(pending); try { parent.postMessage({ type: "kimi-city-growth", ready: true }, location.origin); } catch (_) {} } }, 500);
})();
