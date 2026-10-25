/* 🐜 Ameisenvolk-Overlay für das Neuronale Gehirn der Königin.
 *
 * Rein additiv: eigene DOM+Canvas-Schicht ÜBER dem GPU-Partikelfeld.
 *
 * Bewegungsmodell (v2, "krabbeln statt gleiten"):
 *  - Reynolds-Wander-Steering mit Heading (rad), Speed und wanderAngle;
 *    Kurswechsel nur mit begrenzter, geglätteter Drehrate (~2.4 rad/s).
 *  - Verhaltensschichten: wandern → sammeln (Waypoint) → heim zur Königin →
 *    kurze Pausen (0.4–1.2 s, Speed→0). Aktive Soldaten: schneller, zielstrebiger.
 *  - Bodenebene mit Tiefe: Y-Bewegung = Tiefe (Skalierung + Z-Order),
 *    Sprites bleiben aufrecht (Art ist eine aufrechte 3/4-Figur → kein Rotieren).
 *  - Spiegeln nur mit Hysterese (≥150 ms klare Richtung) und weichem Übergang.
 *  - Körper starr am Boden; volle Sprite-Beine (kein Clip, keine Fake-Beine).
 *    Sprites mit echter Transparenz (keine Beige-/Weiß-Platten). Kein Bob/Flip-Wackeln.
 *  - Ränder: sanftes U-Turn-Steering, KEIN Teleport-Wrap. Separation gegen Überlappung.
 *  - Nur transform pro Frame, ein rAF.
 *
 * NUR Red-Kolonie (Pentest/Bugbounty/WLAN-Soldaten). Blue Queen lebt
 * ausschließlich unter /blue — keine Blue-Soldaten hier.
 * Klick auf eine Ameise öffnet Playbooks/SKILL.md im Detail-Panel.
 */
(function () {
  "use strict";

  var SPR = "/static/sprites/";
  var SPR_V = "?v=20261023s";
  var ROLE_SPRITE = {
    queen:  [SPR + "queen_front.png",       SPR + "queen_tq.png"],
    scout:  [SPR + "scout_front.png",       SPR + "scout_tq.png"],
    worker: [SPR + "worker_front.png",      SPR + "worker_tq.png"],
    def:    [SPR + "soldier_def_front.png", SPR + "soldier_def_tq.png"],
    off:    [SPR + "soldier_off_front.png", SPR + "soldier_off_tq.png"]
  };

  // Red-Soldaten (Brain). Blue-* Namen werden bewusst ausgeschlossen.
  var NAME_ROLE = {
    recon: "scout", osint: "scout", scanning: "scout", takeover: "scout",
    wifi: "off", verify: "off", poc: "off", fuzz: "off", llmsec: "off",
    infra: "def", auth: "def", api: "def", cloud: "def", mobile: "def",
    codeaudit: "worker", analysis: "worker", reporting: "worker", threatintel: "worker"
  };

  function isBlueSoldier(name) {
    if (!name) return false;
    var n = String(name).toLowerCase();
    return n.indexOf("blue") === 0 || n.indexOf("blue-") === 0 ||
      n === "defense" || n === "hardening" || n === "honeypot" ||
      n === "remediation" || n === "swscan" || n.indexOf("blue_") === 0;
  }

  function roleFor(name) {
    if (isBlueSoldier(name)) return null;
    return NAME_ROLE[name] || null;
  }

  var reduce = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function injectStyle() {
    var _st = document.getElementById("ant-colony-style"); if (_st) _st.remove();
    var css = [
      ".ant-colony{position:fixed;left:0;right:0;bottom:0;height:48vh;min-height:320px;",
        "z-index:3;pointer-events:none;overflow:visible;}",
      ".ant-colony::before{content:'';position:absolute;left:0;right:0;bottom:0;height:52%;",
        "background:linear-gradient(180deg,rgba(0,0,0,0) 0%,rgba(8,6,4,0) 18%,",
        "rgba(28,16,6,.38) 68%,rgba(42,22,8,.58) 100%);pointer-events:none;}",
      ".ant-colony canvas.ant-pheromone{display:none!important;position:absolute;inset:0;width:100%;height:100%;",
        "pointer-events:none;}",
      ".ant{position:absolute;left:0;bottom:0;will-change:transform;pointer-events:auto;cursor:pointer;overflow:visible;",
        "transform-origin:50% 100%;filter:drop-shadow(0 4px 8px rgba(0,0,0,.65));",
        "transition:filter .6s ease;}",
      ".ant:focus-visible{outline:2px solid rgba(56,224,255,.7);outline-offset:3px;}",
      ".ant-body{position:absolute;left:0;right:0;top:0;bottom:0;",
        "transform-origin:50% 100%;transform-style:preserve-3d;will-change:transform;",
        "perspective:420px;}",
      ".ant img{display:block;height:100%;width:auto;image-rendering:auto;",
        "transform-origin:50% 88%;",
        "user-select:none;-webkit-user-drag:none;}",
      ".ant.queen{filter:drop-shadow(0 0 18px rgba(255,180,70,.5)) ",
        "drop-shadow(0 8px 16px rgba(0,0,0,.75));}",
      ".ant.active{filter:drop-shadow(0 0 14px rgba(56,224,255,.75)) ",
        "drop-shadow(0 6px 10px rgba(0,0,0,.55));}",
      ".ant .ant-label{position:absolute;left:50%;bottom:100%;transform:translateX(-50%);",
        "margin-bottom:4px;font-size:10px;letter-spacing:.04em;color:#cfe7ff;",
        "direction:ltr;unicode-bidi:isolate;",
        "background:rgba(8,12,20,.78);border:1px solid rgba(56,224,255,.28);",
        "border-radius:7px;padding:2px 7px;white-space:nowrap;opacity:.42;",
        "transition:opacity .45s ease;text-shadow:0 0 6px rgba(56,224,255,.45);",
        "box-shadow:0 0 12px rgba(56,224,255,.12);pointer-events:none;}",
      ".ant.active .ant-label,.ant:hover .ant-label{opacity:.95;}",
      ".ant-colony .ant-caption{position:absolute;left:50%;bottom:6px;transform:translateX(-50%);",
        "font-size:11px;color:#9fd0ff;opacity:.55;letter-spacing:.07em;",
        "pointer-events:none;text-shadow:0 0 10px rgba(0,0,0,.85);",
        "background:rgba(6,10,18,.35);padding:2px 10px;border-radius:999px;",
        "border:1px solid rgba(56,224,255,.12);}",
    ].join("");
    var el = document.createElement("style");
    el.id = "ant-colony-style";
    el.textContent = css;
    document.head.appendChild(el);
  }

  function makeLegs() { return null; }

  function makeAnt(role, cls, heightPx) {
    var wrap = document.createElement("div");
    wrap.className = "ant" + (cls ? " " + cls : "");
    wrap.style.height = heightPx + "px";
    var body = document.createElement("div");
    body.className = "ant-body";
    var pair = ROLE_SPRITE[role] || ROLE_SPRITE.worker;
    var img = document.createElement("img");
    img.src = (cls === "queen" ? pair[0] : pair[1]) + SPR_V;
    img.alt = role + "-Ameise";
    img.loading = "eager";
    img.draggable = false;
    body.appendChild(img);
    wrap.appendChild(body);
    wrap._body = body;
    return wrap;
  }

  // --- State ---------------------------------------------------------------
  var host, pheromoneCv, pheromoneCtx, soldiers = [], queenEl = null, raf = 0;
  var last = 0, hostH = 240, hostW = 800, dpr = 1;
  var TRAIL_MAX = 0; // Spur aus (Judith)
  var TRAIL_LIFE = 9; // s – Spur verblasst
  var TRAIL_MIN_DIST = 2.2; // px between pheromone samples (continuous, not stutter)

  function ensureHost() {
    if (host) return;
    host = document.createElement("div");
    host.className = "ant-colony";
    host.setAttribute("aria-hidden", "true");

    pheromoneCv = document.createElement("canvas");
    pheromoneCv.className = "ant-pheromone";
    host.appendChild(pheromoneCv);
    pheromoneCtx = pheromoneCv.getContext("2d");

    var cap = document.createElement("div");
    cap.className = "ant-caption";
    cap.id = "ant-colony-caption";
    cap.textContent = "🐜 Das Ameisenvolk · Königin + Soldaten";
    host.appendChild(cap);

    var mountTarget = document.querySelector("main") || document.body;
    mountTarget.appendChild(host);

    queenEl = makeAnt("queen", "queen", Math.round(window.innerHeight * 0.32));
    host.appendChild(queenEl);
    layoutQueen();
    resizePheromone();
  }

  function resizePheromone() {
    if (!host || !pheromoneCv) return;
    hostW = host.clientWidth || window.innerWidth;
    hostH = host.clientHeight || Math.round(window.innerHeight * 0.48);
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    pheromoneCv.width = Math.floor(hostW * dpr);
    pheromoneCv.height = Math.floor(hostH * dpr);
    pheromoneCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function layoutQueen() {
    if (!queenEl) return;
    queenEl.style.zIndex = "120";
    // Queen uses transform exclusively (no left thrashing).
    queenEl.style.left = "0";
    queenEl.style.bottom = "0";
  }

  function filterRedSoldiers(soldierNodes) {
    var out = [];
    for (var i = 0; i < soldierNodes.length; i++) {
      var n = soldierNodes[i];
      var name = (n.label || n.id || "").replace(/^soldier:/, "");
      if (roleFor(name)) out.push(n);
    }
    return out;
  }


  function wireSoldierOpen(el, name) {
    if (el.dataset && el.dataset.wiredOpen === "1") return;
    if (el.dataset) el.dataset.wiredOpen = "1";
    el.title = "Playbooks & SKILL.md von " + name + " öffnen";
    el.setAttribute("role", "button");
    el.setAttribute("tabindex", "0");
    el.setAttribute("data-soldier", name);
    function open() {
      window.dispatchEvent(new CustomEvent("antbb-open-soldier", { detail: { name: name } }));
    }
    el.addEventListener("click", function (ev) { ev.stopPropagation(); open(); });
    el.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); }
    });
  }

  function baseSpeed(active, seed) {
    // px/s in der Bodenebene (≈ 0.35–0.6 Körperlängen/s: ruhiges Krabbeln)
    return (active ? 52 : 34) * (0.8 + seed * 0.4);
  }

  function buildColony(soldierNodes) {
    ensureHost();
    soldierNodes = filterRedSoldiers(soldierNodes);

    var byName = {};
    soldiers.forEach(function (s) { byName[s.name] = s; });

    var keep = {};
    var W = hostW || window.innerWidth;
    var baseH = Math.max(72, Math.round(window.innerHeight * 0.12));
    var next = [];
    var n = soldierNodes.length || 1;

    soldierNodes.forEach(function (nd, i) {
      var name = (nd.label || nd.id || "").replace(/^soldier:/, "");
      var role = roleFor(name);
      if (!role) return;
      var findings = (nd.counts && nd.counts.findings) || 0;
      var active = findings > 0;
      var prev = byName[name];

      if (prev) {
        // Kontinuität: Position/Heading/State behalten — KEIN Reset der Bewegung.
        prev.active = active;
        prev.el.classList.toggle("active", active);
        var lab = prev.el.querySelector(".ant-label");
        if (lab) lab.textContent = name + (findings ? " · " + findings : "");
        wireSoldierOpen(prev.el, name);
        prev.baseSpd = baseSpeed(active, prev._seed || 0.5);
        next.push(prev);
        keep[name] = true;
        return;
      }

      var depth = 0.82 + ((i % 5) * 0.06);
      var h = Math.round(baseH * depth);
      var el = makeAnt(role, active ? "active" : "", h);
      var label = document.createElement("span");
      label.className = "ant-label";
      label.textContent = name + (findings ? " · " + findings : "");
      el.appendChild(label);
      wireSoldierOpen(el, name);
      host.appendChild(el);

      var seed = (hashStr(name) % 1000) / 1000;
      var seed2 = (hashStr(name + "#") % 1000) / 1000;
      var heading = seed2 * Math.PI * 2;
      var bs = baseSpeed(active, seed);
      var ant = {
        el: el, body: el._body || null, img: el.querySelector("img"), legs: null,
        name: name, role: role, active: active,
        x: W * (0.06 + 0.88 * ((i + seed * 0.7) / n)),   // gleichmäßig verteilt
        ly: seed2 * bandMaxL(),                          // logische Tiefe
        y: 0,
        heading: heading, omega: 0,
        speed: 0, baseSpd: bs,
        wa: (seed - 0.5) * 2,                            // wanderAngle (relativ)
        state: "wander", stateT: 1 + seed2 * 6,
        wp: null, pauseT: 0,
        face: Math.cos(heading) >= 0 ? 1 : -1, faceX: 0, flipT: 0,
        gait: seed * Math.PI * 2,
        swayPh: seed2 * Math.PI * 2,
        trail: [],
        h: h,
        zBase: depth,
        zLast: -1,
        _seed: seed,
        glow: active ? 1 : 0
      };
      ant.faceX = ant.face;
      ant.y = ant.ly * DEPTH_K;
      next.push(ant);
      keep[name] = true;
    });

    // Entfernte Soldaten (z.B. Blue) aus DOM nehmen.
    soldiers.forEach(function (s) {
      if (!keep[s.name] && s.el && s.el.parentNode) s.el.parentNode.removeChild(s.el);
    });
    soldiers = next;

    var cap = document.getElementById("ant-colony-caption");
    if (cap) {
      cap.textContent = "🐜 Das Ameisenvolk · Königin + " + soldiers.length + " Soldaten";
    }
    if (reduce) renderStatic();
  }

  function hashStr(s) {
    var h = 2166136261;
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }

  // Kürzester Winkel-Delta (−π..π).
  function angDelta(from, to) {
    var d = to - from;
    while (d > Math.PI) d -= Math.PI * 2;
    while (d < -Math.PI) d += Math.PI * 2;
    return d;
  }

  function clamp(v, a, b) { return v < a ? a : (v > b ? b : v); }
  function rnd(a, b) { return a + Math.random() * (b - a); }

  // --- Bodenebene ------------------------------------------------------------
  // Logische Ebene (x, ly); auf dem Bildschirm wird die Tiefe gestaucht (Perspektive).
  var DEPTH_K = 0.5;
  function bandMax() { return hostH * 0.22; }             // Bildschirm-px
  function bandMaxL() { return bandMax() / DEPTH_K; }     // logisch
  var QUEEN_R = 100;                                      // Meidungsradius um die Königin

  var MAX_TURN = 2.4;     // rad/s
  var TURN_SMOOTH = 5.5;  // 1/s – Winkelgeschwindigkeit wird geglättet
  var WANDER_DIST = 46, WANDER_RAD = 26;
  var SEP_DIST = 52;
  var EDGE_M = 120;

  function setState(s, st) {
    s.state = st;
    if (st === "wander") {
      s.stateT = s.active ? rnd(3, 7) : rnd(5, 13);
      s.wp = null;
    } else if (st === "pause") {
      s.pauseT = rnd(0.4, 1.2);
    } else if (st === "forage") {
      var W = hostW || window.innerWidth;
      s.wp = {
        x: rnd(90, Math.max(100, W - 90)),
        ly: rnd(0.05, 0.95) * bandMaxL()
      };
    } else if (st === "home") {
      var W2 = hostW || window.innerWidth;
      var side = Math.random() < 0.5 ? -1 : 1;
      s.wp = {
        x: W2 * 0.5 + side * rnd(QUEEN_R + 30, QUEEN_R + 200),
        ly: rnd(0.02, 0.5) * bandMaxL()
      };
    }
  }

  function afterState(s) {
    // Entscheidet, was als Nächstes kommt.
    var r = Math.random();
    var pForage = s.active ? 0.62 : 0.38;
    if (r < pForage) setState(s, "forage");
    else if (r < pForage + 0.22) setState(s, "pause");
    else setState(s, "wander");
  }

  function updateAnt(s, dt, W, i) {
    var yMaxL = bandMaxL();
    var hx = Math.cos(s.heading), hy = Math.sin(s.heading);

    // --- Verhaltens-State-Machine ---
    var seekX = 0, seekY = 0, hasSeek = false, speedMul = 1, wanderW = 1;
    s.stateT -= dt;
    if (s.state === "wander") {
      if (s.stateT <= 0) afterState(s);
    } else if (s.state === "pause") {
      s.pauseT -= dt;
      speedMul = 0;
      if (s.pauseT <= 0) {
        // Nach Pause: wenn gerade "gesammelt" → heim, sonst wandern/sammeln.
        if (s.afterPause === "home") { s.afterPause = null; setState(s, "home"); }
        else if (s.afterPause === "wander") { s.afterPause = null; setState(s, "wander"); }
        else afterState(s);
      }
    } else if (s.state === "forage" || s.state === "home") {
      var dx = s.wp.x - s.x, dy = s.wp.ly - s.ly;
      var dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 22) {
        s.afterPause = s.state === "forage" ? "home" : "wander";
        setState(s, "pause");
      } else {
        seekX = dx / dist; seekY = dy / dist; hasSeek = true;
        speedMul = (s.state === "forage" ? 1.12 : 1.0) * clamp(dist / 80, 0.4, 1);
        wanderW = s.active ? 0.35 : 0.6; // aktiv: zielstrebiger
      }
    }

    // --- Reynolds-Wander: Kreis vor dem Ant, wanderAngle jittern ---
    var jitter = s.active ? 1.6 : 2.6; // rad/s Random-Walk
    s.wa += (Math.random() - 0.5) * 2 * jitter * dt;
    s.wa *= (1 - 0.35 * dt);           // leichte Rückführung zur Mitte
    s.wa = clamp(s.wa, -1.6, 1.6);
    var wcx = hx * WANDER_DIST, wcy = hy * WANDER_DIST;
    var wtx = wcx + Math.cos(s.heading + s.wa) * WANDER_RAD;
    var wty = wcy + Math.sin(s.heading + s.wa) * WANDER_RAD;
    var wl = Math.sqrt(wtx * wtx + wty * wty) || 1;
    var ax = (wtx / wl) * wanderW, ay = (wty / wl) * wanderW;

    // --- Seek ---
    if (hasSeek) { ax += seekX * 1.6; ay += seekY * 1.6; }

    // --- Ränder: weiches Umkehren (kein Wrap) ---
    var ex = 0, ey = 0;
    if (s.x < EDGE_M) ex += (EDGE_M - s.x) / EDGE_M;
    else if (s.x > W - EDGE_M) ex -= (s.x - (W - EDGE_M)) / EDGE_M;
    var yM = yMaxL * 0.18;
    if (s.ly < yM) ey += (yM - s.ly) / yM;
    else if (s.ly > yMaxL - yM) ey -= (s.ly - (yMaxL - yM)) / yM;
    ax += ex * 3.2; ay += ey * 2.6;

    // --- Königin meiden (nur Körper, nicht der Heimweg-Rand) ---
    var qx = W * 0.5, qdx = s.x - qx;
    if (Math.abs(qdx) < QUEEN_R && s.ly < yMaxL * 0.55) {
      var qf = 1 - Math.abs(qdx) / QUEEN_R;
      ax += (qdx >= 0 ? 1 : -1) * qf * 2.4;
    }

    // --- Separation ---
    var sepX = 0, sepY = 0;
    for (var j = 0; j < soldiers.length; j++) {
      if (j === i) continue;
      var o = soldiers[j];
      var ddx = s.x - o.x, ddy = (s.ly - o.ly) * 1.6; // Tiefe zählt mehr (weniger Platz)
      var dd2 = ddx * ddx + ddy * ddy;
      if (dd2 < SEP_DIST * SEP_DIST && dd2 > 0.01) {
        var dd = Math.sqrt(dd2), f = (1 - dd / SEP_DIST);
        sepX += (ddx / dd) * f; sepY += (ddy / dd) * f;
      } else if (dd2 <= 0.01) { sepX += Math.random() - 0.5; sepY += Math.random() - 0.5; }
    }
    ax += sepX * 1.1; ay += sepY * 1.1;

    // --- Gewünschter Kurs → Drehung mit max. Drehrate und Glättung ---
    var want = (ax * ax + ay * ay > 1e-6) ? Math.atan2(ay, ax) : s.heading;
    var dh = angDelta(s.heading, want);
    var omegaGoal = clamp(dh * 3.2, -MAX_TURN, MAX_TURN);
    if (speedMul === 0) omegaGoal *= 0.15;  // in der Pause kaum drehen
    s.omega += (omegaGoal - s.omega) * (1 - Math.exp(-dt * TURN_SMOOTH));
    s.heading += s.omega * dt;
    if (s.heading > Math.PI) s.heading -= Math.PI * 2;
    else if (s.heading < -Math.PI) s.heading += Math.PI * 2;

    // --- Geschwindigkeit: Kurve bremst, kein Flip-Wackeln ---
    var turnSlow = 1 - 0.45 * Math.min(1, Math.abs(s.omega) / MAX_TURN);
    var goal = s.baseSpd * speedMul * turnSlow;
    var accel = goal > s.speed ? 2.4 : 5.0;
    s.speed += (goal - s.speed) * (1 - Math.exp(-dt * accel));
    if (s.speed < 0.15 && goal === 0) s.speed = 0;

    // --- Integration: fast nur horizontal (kein Tiefen-Wackeln) ---
    s.x += Math.cos(s.heading) * s.speed * dt;
    s.ly += Math.sin(s.heading) * s.speed * dt * 0.10;
    s.x = clamp(s.x, 40, Math.max(60, W - 40));
    s.ly = clamp(s.ly, 0, yMaxL);
    s.y = s.ly * DEPTH_K;

    // --- Blickrichtung: hart umschalten (scaleX ±1). Nie über 0 interpolieren. ---
    var cx = Math.cos(s.heading);
    var intent = s.face;
    if (cx > 0.35) intent = 1; else if (cx < -0.35) intent = -1;
    if (intent !== s.face && s.speed > 3) {
      s.flipT += dt;
      if (s.flipT >= 0.12) { s.face = intent; s.faceX = intent; s.flipT = 0; }
    } else {
      s.flipT = Math.max(0, s.flipT - dt * 2);
      s.faceX = s.face;
    }

    // --- Gangphase an zurückgelegter Strecke ---
    var stride = Math.max(22, s.h * 0.28);
    s.gait += (s.speed / stride) * Math.PI * 2 * dt;

    pushTrail(s, s.x, s.y, s.speed);
  }

  function pushTrail(ant, x, y, speed) {
    if (TRAIL_MAX <= 0) return;
    var t = ant.trail;
    var lastP = t.length ? t[t.length - 1] : null;
    if (speed > 1.5) {
      if (lastP) {
        var dx = x - lastP.x, dy = y - lastP.y;
        if (dx * dx + dy * dy < TRAIL_MIN_DIST * TRAIL_MIN_DIST) return;
      }
      t.push({ x: x, y: y, t: nowSec });
      while (t.length > TRAIL_MAX) t.shift();
    }
  }

  function pruneTrail(s) {
    var t = s.trail;
    while (t.length && nowSec - t[0].t > TRAIL_LIFE) t.shift();
  }

  var nowSec = 0;

  function drawPheromones() {
    if (!pheromoneCtx) return;
    var c = pheromoneCtx;
    c.clearRect(0, 0, hostW, hostH);
    c.lineCap = "round";
    c.lineJoin = "round";
    var BUCKETS = 4;
    for (var i = 0; i < soldiers.length; i++) {
      var s = soldiers[i];
      pruneTrail(s);
      var trail = s.trail, n = trail.length;
      if (n < 2) continue;
      var col = s.active ? "56,224,255" : "210,160,90";
      var amax = s.active ? 0.5 : 0.28;
      var oy = hostH - s.h * 0.1;
      // Ältere Teile blasser/dünner: wenige Polylinien statt hunderter Segmente.
      for (var b = 0; b < BUCKETS; b++) {
        var i0 = Math.floor((n - 1) * b / BUCKETS);
        var i1 = Math.floor((n - 1) * (b + 1) / BUCKETS) + 1;
        if (i1 > n - 1) i1 = n - 1;
        var age = nowSec - trail[i1].t;
        var fade = clamp(1 - age / TRAIL_LIFE, 0, 1);
        var k = (b + 1) / BUCKETS;
        c.beginPath();
        c.moveTo(trail[i0].x, oy - trail[i0].y);
        for (var p = i0 + 1; p <= i1; p++) c.lineTo(trail[p].x, oy - trail[p].y);
        // weicher Schein + Kern
        c.strokeStyle = "rgba(" + col + "," + (amax * 0.35 * k * fade).toFixed(3) + ")";
        c.lineWidth = (s.active ? 5 : 3.5) * (0.5 + 0.5 * k);
        c.stroke();
        c.strokeStyle = "rgba(" + col + "," + (amax * k * fade).toFixed(3) + ")";
        c.lineWidth = (s.active ? 2.2 : 1.4) * (0.55 + 0.45 * k);
        c.stroke();
      }
    }
  }

  // --- Rendering: starrer Körper + 3D-Menschenbeine (Gegenphasengang) --------
  // Klassischer Walk-Cycle (vereinfacht, natürlich):
  //   hip  ≈ +25° vor / −20° zurück
  //   knee ≈ 0° Standstreckung, bis ~55° Beugung in Schwung/Stoß
  //   ankle≈ leichte Absenkung beim Abdruck
  function humanWalk(phase, moving) {
    // phase 0..2π ; return { hip, knee, ankle, lift } in Grad / px-Anteil
    if (!moving) {
      return { hip: 4, knee: 6, ankle: 0, bob: 0 };
    }
    var s = Math.sin(phase);
    var c = Math.cos(phase);
    // Hüfte: Sinus vor/zurück
    var hip = s * 26;
    // Knie: gebeugt in früher Schwungphase (wenn Bein nach vorn, s>0 und c<0 → swing)
    // contact when foot is rear-to-mid (s decreasing through negative)
    var swing = Math.max(0, s);           // 0..1 vorne
    var stance = Math.max(0, -s);         // 0..1 hinten
    var knee = 8 + swing * 48 * (0.35 + 0.65 * Math.max(0, -c)) + stance * 10 * Math.max(0, c);
    // Knöchel: Plantarflexion kurz vor Abdruck
    var ankle = -stance * 18 * Math.max(0, c) + swing * 8;
    return { hip: hip, knee: knee, ankle: ankle, bob: 0 };
  }

  function renderLegs(s, still) {
    var box = s.legs;
    if (!box || !box._legs) return;
    var sp = still ? 0 : s.speed;
    var moving = sp > 2.5;
    var ph = s.gait;
    var L = humanWalk(ph, moving);
    var R = humanWalk(ph + Math.PI, moving); // Gegenphase

    function apply(side, pose, sign) {
      var leg = box._legs[side];
      // 3/4-Ansicht: Pendel in der Bildebene (Z) + Tiefe (X/Y) für Volumen
      leg.root.style.transform =
        "rotateY(" + (sign * 12).toFixed(2) + "deg) translateZ(2px)";
      // Hüfte: Bein nach vorn/hinten (sichtbares Pendel)
      leg.thigh.style.transform =
        "rotateZ(" + (sign * pose.hip).toFixed(2) + "deg) " +
        "rotateX(" + (-10 - pose.hip * 0.2).toFixed(2) + "deg)";
      // Knie: beugen unter dem Oberschenkel
      leg.shin.style.transform =
        "rotateZ(" + (sign * pose.knee * 0.12).toFixed(2) + "deg) " +
        "rotateX(" + (pose.knee).toFixed(2) + "deg)";
      // Fuß: Abrollen
      leg.foot.style.transform =
        "rotateZ(" + (sign * pose.ankle * 0.35).toFixed(2) + "deg) " +
        "rotateX(" + (pose.ankle).toFixed(2) + "deg) translateZ(2px)";
    }
    apply("L", L, -1);
    apply("R", R, 1);
  }

  function renderAnt(s, t, still) {
    var dn = clamp(s.y / Math.max(1, bandMax()), 0, 1);
    var scale = 1 - dn * 0.12;
    var z = 20 + Math.round((1 - dn) * 70);
    if (z !== s.zLast) { s.el.style.zIndex = String(z); s.zLast = z; }

    // Körper starr — kein Bob, keine Neigung. Nur Position + Perspektiv-Scale.
    s.el.style.transform =
      "translate3d(" + s.x.toFixed(2) + "px," + (-s.y).toFixed(2) + "px,0) " +
      "translate(-50%,0) scale(" + scale.toFixed(3) + ")";

    var fx = s.face; // immer exakt ±1, nie über 0 interpolieren
    var body = s.body || (s.el && s.el.querySelector(".ant-body"));
    if (body) {
      body.style.transform = "scaleX(" + fx + ")";
    } else if (s.img) {
      s.img.style.transform = "scaleX(" + fx + ")";
    }
    renderLegs(s, still);
  }

  function renderQueen(t, W) {
    if (!queenEl) return;
    if (!reduce) {
      var breath = 1 + Math.sin(t * 0.9) * 0.008;
      queenEl.style.transform =
        "translate3d(" + (W * 0.5) + "px,0,0) translateX(-50%) scale(" + breath + ")";
    } else {
      queenEl.style.transform =
        "translate3d(" + (W * 0.5) + "px,0,0) translateX(-50%)";
    }
  }

  function renderStatic() {
    var W = hostW || window.innerWidth;
    renderQueen(0, W);
    for (var i = 0; i < soldiers.length; i++) renderAnt(soldiers[i], 0, true);
  }

  function tick(now) {
    var dt = last ? Math.min(0.05, Math.max(0.001, (now - last) / 1000)) : 0.016;
    last = now;
    nowSec = now / 1000;
    var W = hostW || window.innerWidth;

    renderQueen(nowSec, W);
    for (var i = 0; i < soldiers.length; i++) {
      var s = soldiers[i];
      updateAnt(s, dt, W, i);
      renderAnt(s, nowSec, false);
    }
    drawPheromones();
    raf = requestAnimationFrame(tick);
  }

  var started = false;
  function start(soldierNodes) {
    injectStyle();
    buildColony(soldierNodes);
    if (started) return;           // 20s-Refresh: nur Labels/Aktivität, Bewegung läuft weiter
    started = true;
    resizePheromone();
    if (reduce) { renderStatic(); return; }
    last = 0;
    raf = requestAnimationFrame(tick);
  }

  function loadAndStart() {
    fetch("/api/brain/nodes")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (g) {
        var sol = (g && g.nodes ? g.nodes : []).filter(function (n) {
          return n.type === "soldier" && !isBlueSoldier((n.label || n.id || "").replace(/^soldier:/, ""));
        });
        if (!sol.length) {
          sol = Object.keys(NAME_ROLE).map(function (name) {
            return { type: "soldier", label: name, id: "soldier:" + name, counts: { findings: 0 } };
          });
        }
        start(sol);
      })
      .catch(function () {
        start(Object.keys(NAME_ROLE).map(function (name) {
          return { type: "soldier", label: name, id: "soldier:" + name, counts: { findings: 0 } };
        }));
      });
  }

  // Status-Refresh: nur Labels/Aktivität — Positionen/Heading bleiben (kein Rebuild).
  function schedule() { setInterval(loadAndStart, 20000); }

  function init() { loadAndStart(); schedule(); }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", init);
  else init();

  window.addEventListener("resize", function () {
    if (queenEl) queenEl.style.height = Math.round(window.innerHeight * 0.32) + "px";
    resizePheromone();
    var W = hostW || window.innerWidth;
    for (var i = 0; i < soldiers.length; i++) {
      soldiers[i].x = clamp(soldiers[i].x, 40, Math.max(60, W - 40));
      soldiers[i].ly = clamp(soldiers[i].ly, 0, bandMaxL());
    }
    if (reduce) renderStatic();
  });
})();
