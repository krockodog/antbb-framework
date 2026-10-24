/* 🐜 Ameisenvolk-Overlay für das gemeinsame Neuronale Gehirn (Superhirn).
 *
 * Rein additiv und nicht-destruktiv: legt eine eigene DOM-Schicht ÜBER das
 * GPU-Partikelfeld (brain-canvas), ohne die three.js-Engine oder das
 * Knoten-Panel zu berühren. Nutzt die von der Nutzerin gestalteten Sprites
 * (web/static/sprites/*). Die REPARIERTE Königin (Fühler + freie Arme + Stab)
 * steht prominent in der Mitte; die Soldaten krabbeln als Ameisen umher.
 *
 * NEU: Drei Teams in ihrer Teamfarbe sichtbar — Rot, Blau, Gelb. Jede Ameise
 * wird nach ihrem Team eingefärbt (CSS-Filter auf die Sprites, kein Bloom,
 * kein Additive-Blending, keine grellen Wirbel). Teams gruppieren sich links
 * (Rot), Mitte (Blau), rechts (Gelb) um die Königin. Aktive Soldaten (Funde
 * bzw. laufender Scan) bewegen sich lebhafter und bekommen einen dezenten
 * Glow in ihrer Teamfarbe. Pointer-events: none → fängt keine Klicks ab.
 *
 * Keine Secrets, keine PII. Läuft auch mit leerer DB (ruhiges 3-Team-Volk).
 */
(function () {
  "use strict";

  var SPR = "/static/sprites/";
  // Rolle → Sprite-Paar (front / dreiviertel). Nur echte, vorhandene Assets.
  var ROLE_SPRITE = {
    queen:   [SPR + "queen_front.png",       SPR + "queen_tq.png"],
    scout:   [SPR + "scout_front.png",       SPR + "scout_tq.png"],
    worker:  [SPR + "worker_front.png",      SPR + "worker_tq.png"],
    def:     [SPR + "soldier_def_front.png", SPR + "soldier_def_tq.png"],
    off:     [SPR + "soldier_off_front.png", SPR + "soldier_off_tq.png"]
  };

  // Soldaten-Name → Rolle (Sprite-Zuordnung passend zur Aufgabe des Soldaten).
  var NAME_ROLE = {
    recon: "scout", osint: "scout", scanning: "scout", takeover: "scout",
    wifi: "off", verify: "off", poc: "off", fuzz: "off", llmsec: "off",
    infra: "def", auth: "def", api: "def", cloud: "def", mobile: "def",
    codeaudit: "worker", analysis: "worker", reporting: "worker", threatintel: "worker",
    // Blau (Schutz/Hardening)
    swscan: "scout", hardening: "def", remediation: "worker", defense: "off",
    honeypot: "def", greenbone: "scout", patch: "worker", detection: "off",
    // Gelb (Reverse Engineering)
    doctor: "worker", intake: "scout", strings: "worker", "elf-macho": "def",
    "pe-exe": "def", apk: "off", dotnet: "def", ghidra: "scout",
    "malware-triage": "off", dossier: "worker"
  };

  // Team → Farbwerte. Basis-Sprites sind rot/gold; Blau/Gelb per Hue-Rotate.
  var TEAM = {
    red:    { filter: "saturate(1.08)",                                 glow: "255,70,70",   label: "Rot" },
    blue:   { filter: "hue-rotate(185deg) saturate(1.2)",               glow: "70,150,255",  label: "Blau" },
    yellow: { filter: "hue-rotate(28deg) saturate(1.25) brightness(1.06)", glow: "255,208,70",  label: "Gelb" }
  };
  var TEAM_ORDER = ["red", "blue", "yellow"];

  // Repräsentative Soldaten je Team (Fallback, wenn die DB noch leer ist).
  var TEAM_SOLDIERS = {
    red:    ["recon", "osint", "scanning", "auth", "api", "fuzz", "verify", "poc",
             "cloud", "mobile", "infra", "takeover", "codeaudit", "analysis",
             "reporting", "threatintel", "llmsec", "wifi"],
    blue:   ["swscan", "hardening", "remediation", "defense", "honeypot",
             "greenbone", "patch", "detection"],
    yellow: ["doctor", "intake", "strings", "elf-macho", "pe-exe", "apk",
             "dotnet", "ghidra", "malware-triage", "dossier"]
  };

  function roleFor(name) { return NAME_ROLE[name] || "worker"; }

  // Team aus einem Brain-Node ableiten (team/colony/queen/Präfix), sonst rot.
  function teamFor(n) {
    var t = (n && (n.team || n.colony || n.queen || "")).toString().toLowerCase();
    if (t.indexOf("blue") >= 0 || t.indexOf("blau") >= 0) return "blue";
    if (t.indexOf("yellow") >= 0 || t.indexOf("gelb") >= 0) return "yellow";
    if (t.indexOf("red") >= 0 || t.indexOf("rot") >= 0) return "red";
    var id = (n && (n.id || n.label || "")).toString().toLowerCase();
    if (/(^|:)(blue|blau)/.test(id)) return "blue";
    if (/(^|:)(yellow|gelb)/.test(id)) return "yellow";
    return "red";
  }

  var reduce = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // --- Overlay-Container + minimaler Style (gekapselt, kein globaler Leak) ---
  function injectStyle() {
    if (document.getElementById("ant-colony-style")) return;
    var css = [
      ".ant-colony{position:fixed;left:0;right:0;bottom:0;height:34vh;min-height:230px;",
        "z-index:3;pointer-events:none;overflow:hidden;}",
      ".ant-colony::before{content:'';position:absolute;left:0;right:0;bottom:0;height:46%;",
        "background:linear-gradient(180deg,rgba(0,0,0,0) 0%,rgba(10,7,4,.0) 20%,",
        "rgba(30,18,8,.32) 70%,rgba(40,22,8,.5) 100%);}",
      ".ant{position:absolute;bottom:0;will-change:transform;",
        "transform-origin:50% 100%;filter:drop-shadow(0 6px 10px rgba(0,0,0,.6));}",
      ".ant img{display:block;height:100%;width:auto;image-rendering:auto;}",
      /* Team-Einfärbung der Sprites (kein Bloom/Additive, nur CSS-Filter) */
      ".ant.team-red img{filter:saturate(1.08);}",
      ".ant.team-blue img{filter:hue-rotate(185deg) saturate(1.2);}",
      ".ant.team-yellow img{filter:hue-rotate(28deg) saturate(1.25) brightness(1.06);}",
      /* Königin bleibt in ihrer echten Farbe, dezenter warmer Schatten */
      ".ant.queen{filter:drop-shadow(0 0 14px rgba(255,180,70,.4)) ",
        "drop-shadow(0 8px 14px rgba(0,0,0,.7));}",
      /* aktive Ameise: dezenter Glow in TEAMFARBE (per CSS-Variable) */
      ".ant.active{filter:drop-shadow(0 0 11px rgba(var(--team-glow),.7)) ",
        "drop-shadow(0 6px 10px rgba(0,0,0,.6));}",
      ".ant .ant-label{position:absolute;left:50%;bottom:100%;transform:translateX(-50%);",
        "margin-bottom:3px;font-size:10px;letter-spacing:.03em;color:#eef3fb;",
        "background:rgba(8,12,20,.72);border:1px solid rgba(var(--team-glow),.4);",
        "border-radius:6px;padding:1px 6px;white-space:nowrap;opacity:0;",
        "transition:opacity .4s;}",
      ".ant:hover .ant-label{opacity:1;}",
      ".ant-caption{position:absolute;left:50%;top:6px;transform:translateX(-50%);",
        "font-size:11px;color:#9fd0ff;opacity:.55;letter-spacing:.06em;",
        "pointer-events:none;text-shadow:0 0 8px rgba(0,0,0,.8);}",
      /* kleine Team-Legende unten */
      ".ant-legend{position:absolute;right:12px;bottom:10px;display:flex;gap:10px;",
        "font-size:11px;color:#cfe7ff;opacity:.8;}",
      ".ant-legend b{display:inline-block;width:9px;height:9px;border-radius:50%;",
        "margin-right:4px;vertical-align:middle;}"
    ].join("");
    var st = document.createElement("style");
    st.id = "ant-colony-style";
    st.textContent = css;
    document.head.appendChild(st);
  }

  function makeAnt(role, cls, h, team) {
    var el = document.createElement("div");
    el.className = "ant" + (cls ? " " + cls : "") + (team ? " team-" + team : "");
    if (team && TEAM[team]) el.style.setProperty("--team-glow", TEAM[team].glow);
    el.style.height = h + "px";
    var img = document.createElement("img");
    var pair = ROLE_SPRITE[role] || ROLE_SPRITE.worker;
    img.alt = "";
    img.src = cls === "queen" ? pair[0] : pair[1];
    el.appendChild(img);
    return el;
  }

  var host, soldiers = [], queenEl = null, raf = 0;

  function buildColony(soldierNodes) {
    if (!host) {
      host = document.createElement("div");
      host.className = "ant-colony";
      host.setAttribute("aria-hidden", "true");
      var cap = document.createElement("div");
      cap.className = "ant-caption";
      cap.textContent = "🐜 Superhirn · Königin + " + soldierNodes.length +
        " Soldaten aus 3 Teams";
      host.appendChild(cap);
      var mountTarget = document.querySelector("main") || document.body;
      mountTarget.appendChild(host);

      // Reparierte Königin prominent in der Mitte (queen_front: Fühler+Arme+Stab).
      queenEl = makeAnt("queen", "queen", Math.round(window.innerHeight * 0.26));
      host.appendChild(queenEl);

      // Team-Legende
      var leg = document.createElement("div");
      leg.className = "ant-legend";
      leg.innerHTML = TEAM_ORDER.map(function (t) {
        return "<span><b style=\"background:rgb(" + TEAM[t].glow + ")\"></b>" +
          TEAM[t].label + "</span>";
      }).join("");
      host.appendChild(leg);
    }

    soldiers.forEach(function (s) { if (s.el && s.el.parentNode) s.el.parentNode.removeChild(s.el); });
    soldiers = [];

    var W = window.innerWidth;
    var baseH = Math.max(70, Math.round(window.innerHeight * 0.12));

    // Team-Zonen: Rot links, Blau Mitte, Gelb rechts (um die Königin herum).
    var zones = {
      red:    [0.02 * W, 0.30 * W],
      blue:   [0.36 * W, 0.64 * W],
      yellow: [0.70 * W, 0.98 * W]
    };

    soldierNodes.forEach(function (n, i) {
      var name = (n.label || n.id || "").replace(/^soldier:/, "").replace(/^(red|blue|yellow):/, "");
      var team = n._team || teamFor(n);
      var role = roleFor(name);
      var findings = (n.counts && n.counts.findings) || 0;
      var active = findings > 0;
      var depth = 0.82 + ((i % 5) * 0.06);
      var h = Math.round(baseH * depth);
      var el = makeAnt(role, active ? "active" : "", h, team);
      var label = document.createElement("span");
      label.className = "ant-label";
      label.textContent = name + (findings ? " · " + findings : "");
      el.appendChild(label);
      host.appendChild(el);

      var zone = zones[team] || zones.red;
      var x0 = zone[0], x1 = zone[1];
      soldiers.push({
        el: el, name: name, team: team, active: active,
        x: x0 + Math.random() * (x1 - x0),
        lo: x0 - 30, hi: x1 + 30,              // bleibt grob in der Team-Zone
        vx: (Math.random() < 0.5 ? -1 : 1) * (active ? 13 : 7) * (0.6 + Math.random() * 0.8),
        bob: Math.random() * Math.PI * 2,
        bobSpd: (active ? 5.0 : 3.2) + Math.random() * 1.5,
        yOff: (i % 5) * (baseH * 0.12),
        h: h, face: 1, z: Math.round(depth * 100)
      });
      el.style.zIndex = String(soldiers[soldiers.length - 1].z);
    });

    layoutStatic();
  }

  function layoutStatic() {
    if (queenEl) {
      queenEl.style.left = "50%";
      queenEl.style.transform = "translateX(-50%)";
      queenEl.style.zIndex = "120";
    }
  }

  var last = 0;
  function tick(now) {
    var dt = last ? Math.min(0.05, (now - last) / 1000) : 0.016;
    last = now;
    for (var i = 0; i < soldiers.length; i++) {
      var s = soldiers[i];
      if (!reduce) {
        s.x += s.vx * dt;
        s.bob += s.bobSpd * dt;
        // in der Team-Zone auf und ab wandern (sanftes Abprallen)
        if (s.x < s.lo) { s.x = s.lo; s.vx = Math.abs(s.vx); }
        else if (s.x > s.hi) { s.x = s.hi; s.vx = -Math.abs(s.vx); }
        s.face = s.vx >= 0 ? 1 : -1;
      }
      var bobY = reduce ? 0 : Math.sin(s.bob) * (s.active ? 5 : 3);
      var tilt = reduce ? 0 : Math.sin(s.bob) * (s.active ? 2.4 : 1.4);
      s.el.style.left = s.x + "px";
      s.el.style.bottom = s.yOff + "px";
      s.el.style.transform =
        "scaleX(" + s.face + ") translateY(" + (-bobY) + "px) rotate(" + tilt + "deg)";
    }
    raf = requestAnimationFrame(tick);
  }

  function start(soldierNodes) {
    injectStyle();
    buildColony(soldierNodes);
    if (raf) cancelAnimationFrame(raf);
    last = 0;
    raf = requestAnimationFrame(tick);
  }

  // Fallback-Volk aus allen drei Teams (ruhig, ohne Funde).
  function fallbackColony() {
    var out = [];
    TEAM_ORDER.forEach(function (t) {
      TEAM_SOLDIERS[t].forEach(function (name) {
        out.push({ type: "soldier", label: name, id: t + ":" + name,
                   _team: t, counts: { findings: 0 } });
      });
    });
    return out;
  }

  function loadAndStart() {
    fetch("/api/brain/nodes")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (g) {
        var sol = (g && g.nodes ? g.nodes : []).filter(function (n) { return n.type === "soldier"; });
        if (!sol.length) { start(fallbackColony()); return; }
        // Team pro Node ermitteln; falls ALLE rot (nur 1 Kolonie gemeldet),
        // trotzdem die 3 Teams zeigen (gemeinsames Superhirn).
        sol.forEach(function (n) { n._team = teamFor(n); });
        var teamsSeen = {};
        sol.forEach(function (n) { teamsSeen[n._team] = 1; });
        if (Object.keys(teamsSeen).length < 2) {
          start(fallbackColony());
        } else {
          start(sol);
        }
      })
      .catch(function () { start(fallbackColony()); });
  }

  function schedule() { setInterval(loadAndStart, 20000); }
  function init() { loadAndStart(); schedule(); }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", init);
  else init();

  window.addEventListener("resize", function () {
    if (queenEl) queenEl.style.height = Math.round(window.innerHeight * 0.26) + "px";
  });
})();
