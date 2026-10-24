/* 🐜 Ameisenvolk-Overlay für das Neuronale Gehirn der Königin.
 *
 * Rein additiv und nicht-destruktiv: legt eine eigene DOM-Schicht ÜBER das
 * GPU-Partikelfeld (brain-canvas), ohne die three.js-Engine oder das
 * Knoten-Panel zu berühren. Nutzt die von der Nutzerin gestalteten Sprites
 * (web/static/sprites/*). Die Königin steht prominent, die 18 Soldaten
 * krabbeln als Arbeiter/Späher/Soldaten-Ameisen umher. Aktive Soldaten
 * (mit Funden bzw. laufendem Scan) werden hervorgehoben und bewegen sich
 * lebhafter. Pointer-events: none → das Overlay fängt keine Klicks ab.
 *
 * Keine Secrets, keine PII. Läuft auch mit leerer DB (dann ruhiges Krabbeln).
 */
(function () {
  "use strict";

  var SPR = "/static/sprites/";
  // --- Teams (echte Soldaten-Rosters aus antbb/agents/*) ---------------------
  var ROSTER = {
    red:   ["analysis","api","auth","cloud","codeaudit","fuzz","infra","llmsec",
            "mobile","osint","poc","recon","reporting","scanning","ssrf",
            "takeover","threatintel","verify","wifi"],
    blue:  ["attacklog","audit","backup","backupverify","credhygiene","defense",
            "fwaudit","hardening","honeypot","idhygiene","incident","logging",
            "logintegrity","netdef","patchmgmt","patchverify","remediation",
            "supplychain","swscan","ticketclose","tlsposture","vulnticket",
            "watcher","webharden"],
    yellow:["apk","doctor","dossier","dotnet","elf_macho","ghidra","intake",
            "malware_triage","pe_exe","strings_crypto"]
  };
  var TEAM = {
    red:    { label: "Rot",  dot: "#ff5a46" },
    blue:   { label: "Blau", dot: "#39c2ff" },
    yellow: { label: "Gelb", dot: "#ffce3a" }
  };
  var TEAM_ORDER = ["red","blue","yellow"];
  var TEAM_OF = {};
  Object.keys(ROSTER).forEach(function (tk) {
    ROSTER[tk].forEach(function (n) { TEAM_OF[n] = tk; });
  });
  function teamFor(node, name) {
    var t = node && (node.team || node.colony || node.queen);
    if (t && TEAM[String(t).toLowerCase()]) return String(t).toLowerCase();
    return TEAM_OF[name] || "red";
  }

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
    codeaudit: "worker", analysis: "worker", reporting: "worker", threatintel: "worker"
  };

  function roleFor(name) { return NAME_ROLE[name] || "worker"; }

  var reduce = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // --- Overlay-Container + minimaler Style (gekapselt, kein globaler Leak) ---
  function injectStyle() {
    if (document.getElementById("ant-colony-style")) return;
    var css = [
      ".ant-colony{position:fixed;left:0;right:0;bottom:0;height:34vh;min-height:230px;",
        "z-index:3;pointer-events:none;overflow:hidden;}",
      /* dezenter Boden, passt zum Schwarz/Bloom-Theme */
      ".ant-colony::before{content:'';position:absolute;left:0;right:0;bottom:0;height:46%;",
        "background:linear-gradient(180deg,rgba(0,0,0,0) 0%,rgba(10,7,4,.0) 20%,",
        "rgba(30,18,8,.32) 70%,rgba(40,22,8,.5) 100%);}",
      ".ant{position:absolute;bottom:0;will-change:transform;",
        "transform-origin:50% 100%;filter:drop-shadow(0 6px 10px rgba(0,0,0,.6));}",
      ".ant img{display:block;height:100%;width:auto;image-rendering:auto;}",
      ".ant.queen{filter:drop-shadow(0 0 16px rgba(255,180,70,.45)) ",
        "drop-shadow(0 8px 14px rgba(0,0,0,.7));}",
      ".ant.active{filter:drop-shadow(0 0 12px rgba(56,224,255,.7)) ",
        "drop-shadow(0 6px 10px rgba(0,0,0,.6));}",
      ".ant .ant-label{position:absolute;left:50%;bottom:100%;transform:translateX(-50%);",
        "margin-bottom:3px;font-size:10px;letter-spacing:.03em;color:#cfe7ff;",
        "background:rgba(8,12,20,.7);border:1px solid rgba(56,224,255,.25);",
        "border-radius:6px;padding:1px 6px;white-space:nowrap;opacity:0;",
        "transition:opacity .4s;text-shadow:0 0 6px rgba(56,224,255,.4);}",
      ".ant.active .ant-label{opacity:.92;}",
      ".ant.team-red img{filter:saturate(1.15) drop-shadow(0 0 7px rgba(255,90,70,.55));}",
      ".ant.team-blue img{filter:saturate(1.2) hue-rotate(190deg) drop-shadow(0 0 7px rgba(57,194,255,.6));}",
      ".ant.team-yellow img{filter:saturate(1.3) hue-rotate(35deg) brightness(1.06) drop-shadow(0 0 7px rgba(255,206,58,.6));}",
      ".ant .ant-label{opacity:.9;}",
      ".ant.team-red .ant-label{color:#ffd3cb;border-color:rgba(255,90,70,.5);text-shadow:0 0 6px rgba(255,90,70,.5);}",
      ".ant.team-blue .ant-label{color:#cfeaff;border-color:rgba(57,194,255,.5);text-shadow:0 0 6px rgba(57,194,255,.5);}",
      ".ant.team-yellow .ant-label{color:#fff0c0;border-color:rgba(255,206,58,.55);text-shadow:0 0 6px rgba(255,206,58,.5);}",
      ".ant-nodes{position:fixed;inset:0;z-index:2;pointer-events:none;overflow:hidden;}",
      ".ant-node{position:absolute;width:7px;height:7px;border-radius:50%;",
        "transform:translate(-50%,-50%);will-change:opacity,transform;",
        "animation:antNodePulse 3.4s ease-in-out infinite;}",
      ".ant-node .ant-node-lbl{position:absolute;left:10px;top:-2px;font-size:9px;",
        "white-space:nowrap;opacity:.7;letter-spacing:.02em;}",
      "@keyframes antNodePulse{0%,100%{opacity:.22;transform:translate(-50%,-50%) scale(.8);}",
        "50%{opacity:.95;transform:translate(-50%,-50%) scale(1.25);}}",
      ".ant-colony .ant-caption{position:absolute;left:50%;bottom:4px;transform:translateX(-50%);",
        "font-size:11px;color:#9fd0ff;opacity:.5;letter-spacing:.06em;",
        "pointer-events:none;text-shadow:0 0 8px rgba(0,0,0,.8);}"
    ].join("");
    var el = document.createElement("style");
    el.id = "ant-colony-style";
    el.textContent = css;
    document.head.appendChild(el);
  }

  function makeAnt(role, cls, heightPx) {
    var wrap = document.createElement("div");
    wrap.className = "ant" + (cls ? " " + cls : "");
    wrap.style.height = heightPx + "px";
    var pair = ROLE_SPRITE[role] || ROLE_SPRITE.worker;
    var img = document.createElement("img");
    // Dreiviertel-Ansicht für die krabbelnden Soldaten wirkt lebendiger,
    // Frontansicht für die stehende Königin.
    img.src = cls === "queen" ? pair[0] : pair[1];
    img.alt = role + "-Ameise";
    img.loading = "eager";
    wrap.appendChild(img);
    return wrap;
  }

  var host, soldiers = [], queenEl = null, raf = 0;

  function buildColony(soldierNodes) {
    if (!host) {
      host = document.createElement("div");
      host.className = "ant-colony";
      host.setAttribute("aria-hidden", "true");
      var cap = document.createElement("div");
      cap.className = "ant-caption";
      cap.textContent = "🐜 Das Ameisenvolk · Königin + " + soldierNodes.length + " Soldaten";
      host.appendChild(cap);
      // In den Haupt-Inhaltsbaum einhängen (nicht body): stellt sicher, dass das
      // Overlay zuverlässig ÜBER dem WebGL-Partikelfeld kompositiert wird.
      var mountTarget = document.querySelector("main") || document.body;
      mountTarget.appendChild(host);

      // Königin prominent in der Mitte.
      queenEl = makeAnt("queen", "queen", Math.round(window.innerHeight * 0.26));
      host.appendChild(queenEl);
    }

    // Vorhandene Soldaten-Ameisen entfernen und neu aufbauen (Status-Refresh).
    soldiers.forEach(function (s) { if (s.el && s.el.parentNode) s.el.parentNode.removeChild(s.el); });
    soldiers = [];

    var W = window.innerWidth;
    var baseH = Math.max(70, Math.round(window.innerHeight * 0.12));
    // Soldaten nach Team gruppieren (Farb-Zonen entlang der Breite)
    var byTeam = { red: [], blue: [], yellow: [] };
    soldierNodes.forEach(function (n) {
      var nm = (n.label || n.id || "").replace(/^soldier:/, "");
      (byTeam[teamFor(n, nm)] || byTeam.red).push(n);
    });
    var ZONE = { red: [0.02, 0.31], blue: [0.355, 0.645], yellow: [0.69, 0.98] };
    var idx = 0;
    TEAM_ORDER.forEach(function (tk) {
      var list = byTeam[tk];
      var z = ZONE[tk], xmin = z[0] * W, xmax = z[1] * W, span = Math.max(40, xmax - xmin);
      list.forEach(function (n, j) {
        var name = (n.label || n.id || "").replace(/^soldier:/, "");
        var role = roleFor(name);
        var findings = (n.counts && n.counts.findings) || 0;
        var active = findings > 0;
        var depth = 0.82 + ((idx % 5) * 0.06);
        var h = Math.round(baseH * depth);
        var el = makeAnt(role, (active ? "active " : "") + "team-" + tk, h);
        var label = document.createElement("span");
        label.className = "ant-label";
        label.textContent = name + (findings ? " \u00b7 " + findings : "");
        el.appendChild(label);
        host.appendChild(el);
        soldiers.push({
          el: el, name: name, active: active, team: tk,
          xmin: xmin, xmax: xmax,
          x: xmin + Math.random() * span,
          vx: (Math.random() < 0.5 ? -1 : 1) * (active ? 14 : 7) * (0.6 + Math.random() * 0.8),
          bob: Math.random() * Math.PI * 2,
          bobSpd: (active ? 5.2 : 3.2) + Math.random() * 1.5,
          yOff: (j % 5) * (baseH * 0.12),
          h: h, face: 1, z: Math.round(depth * 100)
        });
        el.style.zIndex = String(soldiers[soldiers.length - 1].z);
        idx++;
      });
    });
    buildNodeField(soldierNodes);

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
    var W = window.innerWidth;
    for (var i = 0; i < soldiers.length; i++) {
      var s = soldiers[i];
      if (!reduce) {
        s.x += s.vx * dt;
        s.bob += s.bobSpd * dt;
        var lo = (s.xmin != null ? s.xmin : 0) - 40;
        var hi = (s.xmax != null ? s.xmax : W) + 40;
        if (s.x < lo) { s.x = hi; }
        else if (s.x > hi) { s.x = lo; }
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

  function buildNodeField(soldierNodes) {
    var old = document.getElementById("ant-nodes");
    if (old && old.parentNode) old.parentNode.removeChild(old);
    var layer = document.createElement("div");
    layer.className = "ant-nodes"; layer.id = "ant-nodes";
    layer.setAttribute("aria-hidden", "true");
    var grp = { red: [], blue: [], yellow: [] };
    soldierNodes.forEach(function (n) {
      var nm = (n.label || n.id || "").replace(/^soldier:/, "");
      (grp[teamFor(n, nm)] || grp.red).push(nm);
    });
    var XR = { red: [0.18, 0.42], blue: [0.40, 0.62], yellow: [0.58, 0.82] };
    TEAM_ORDER.forEach(function (tk) {
      var names = grp[tk], xr = XR[tk], col = TEAM[tk].dot, nmax = names.length || 1;
      names.forEach(function (nm, i) {
        var dot = document.createElement("span");
        dot.className = "ant-node";
        var fx = xr[0] + (xr[1] - xr[0]) * ((i + 0.5) / nmax);
        var fy = 0.12 + 0.46 * (((i * 37) % 100) / 100);
        dot.style.left = (fx * 100).toFixed(1) + "%";
        dot.style.top = (fy * 100).toFixed(1) + "%";
        dot.style.background = col;
        dot.style.boxShadow = "0 0 8px " + col + ", 0 0 16px " + col;
        dot.style.animationDelay = ((i % 10) * 0.28).toFixed(2) + "s";
        dot.title = nm;
        layer.appendChild(dot);
      });
    });
    var mt = document.querySelector("main") || document.body;
    mt.appendChild(layer);
  }

  function rosterSoldiers() {
    var out = [];
    TEAM_ORDER.forEach(function (tk) {
      ROSTER[tk].forEach(function (name) {
        out.push({ type: "soldier", label: name, id: "soldier:" + name,
                   team: tk, counts: { findings: 0 } });
      });
    });
    return out;
  }

  function mergeRoster(live) {
    var have = {}, out = [];
    (live || []).forEach(function (n) {
      var nm = (n.label || n.id || "").replace(/^soldier:/, "");
      if (!n.team) n.team = teamFor(n, nm);
      have[nm] = true; out.push(n);
    });
    rosterSoldiers().forEach(function (n) {
      if (!have[n.label]) { have[n.label] = true; out.push(n); }
    });
    return out;
  }

  function start(soldierNodes) {
    injectStyle();
    buildColony(soldierNodes);
    if (raf) cancelAnimationFrame(raf);
    last = 0;
    raf = requestAnimationFrame(tick);
  }

  function loadAndStart() {
    fetch("/api/brain/nodes")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (g) {
        var sol = (g && g.nodes ? g.nodes : []).filter(function (n) { return n.type === "soldier"; });
        // Immer alle 3 Teams zeigen: Live-Soldaten + fehlende aus echtem Roster.
        start(mergeRoster(sol));
      })
      .catch(function () { start(mergeRoster([])); });
  }

  // Periodischer Status-Refresh (an Soldaten-Aktivität gekoppelt), schonend.
  function schedule() { setInterval(loadAndStart, 20000); }

  function init() { loadAndStart(); schedule(); }
  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", init);
  else init();

  window.addEventListener("resize", function () {
    // leichte Re-Layout-Hilfe bei Größenänderung (kein Vollneuaufbau nötig)
    if (queenEl) queenEl.style.height = Math.round(window.innerHeight * 0.26) + "px";
  });
})();
