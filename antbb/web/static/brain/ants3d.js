// Neural Brain city overlay — Judith's vendored Kimi 3D ant metropolis
// (static/brain/kimi-city) as the environment. engine.js / generators.js untouched.
// Requirements kept: Red capital center + kneeling scout, Blue left, Yellow right,
// front-facing ants (in her city), compact badges from live /api/soldiers, fine trails.
(async function () {
  const host = document.createElement("div");
  host.id = "kimi-city-host";
  // z-index 1 < main (z-index 2): /brain-Bedienelemente bleiben klickbar, leere Flaechen orbiten die Stadt
  host.style.cssText = "position:fixed;inset:0;z-index:1;pointer-events:none;";
  const iframe = document.createElement("iframe");
  iframe.id = "kimi-city-frame";
  iframe.title = "Ameisenmetropole — Neural Brain City";
  iframe.src = "/static/brain/kimi-city/index.html?embed=1";
  iframe.style.cssText = "position:absolute;inset:0;width:100%;height:100%;border:0;pointer-events:auto;background:transparent;";
  iframe.allow = "fullscreen";
  host.appendChild(iframe);
  document.body.appendChild(host);

  // Hide 2D colony sprites — city is the showpiece
  const css = document.createElement("style");
  css.textContent = `
    .ant.queen,.ant-colony .ant{display:none!important}
    .ant-colony canvas.ant-pheromone{opacity:.25}
    #kimi-city-badges{position:fixed;inset:0;pointer-events:none;z-index:4}
    .kimi-badge{position:absolute;transform:translate(-50%,0);font:8px/1.15 system-ui,sans-serif;
      color:#eef;background:rgba(4,8,18,.78);border:1px solid;border-left-width:2px;border-radius:3px;
      padding:2px 5px;max-width:72px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
      pointer-events:auto;cursor:help;backdrop-filter:blur(2px)}
    .kimi-badge b,.kimi-badge span{display:block;overflow:hidden;text-overflow:ellipsis}
    .kimi-badge span{font-size:7px;color:#bcd;opacity:.9}
    .kimi-badge.red{border-color:#ff3b3b}.kimi-badge.blue{border-color:#3b8bff}.kimi-badge.yellow{border-color:#ffd23b}
    .kimi-badge.queen{font-size:11px;max-width:140px;padding:4px 7px;border-width:2px;border-left-width:4px}
    .kimi-badge.queen.red{background:rgba(50,6,6,.9);color:#ffd96b}
    #a3d-trails{position:fixed;inset:0;pointer-events:none;z-index:3}
    #brain-tl-bar{max-width:260px!important;transform:scale(.85);transform-origin:bottom left;opacity:.78!important}
  `;
  document.head.appendChild(css);
  // Let the city read as the primary world; particle brain remains running underneath.
  const bc=document.getElementById('brain-canvas');
  if(bc){ bc.style.opacity='0.22'; bc.style.filter='saturate(1.2)'; }


  // Fine neural pheromone trails (purple/cyan accents harmonizing with brain theme)
  const trailCv = document.createElement("canvas");
  trailCv.id = "a3d-trails";
  document.body.appendChild(trailCv);
  const tctx = trailCv.getContext("2d");
  function resizeTrails() {
    const dpr = Math.min(devicePixelRatio, 2);
    trailCv.width = Math.floor(innerWidth * dpr);
    trailCv.height = Math.floor(innerHeight * dpr);
    trailCv.style.width = innerWidth + "px";
    trailCv.style.height = innerHeight + "px";
    tctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  resizeTrails();
  addEventListener("resize", resizeTrails);

  const W = () => innerWidth, H = () => innerHeight;
  // District hubs in screen space (matches her elevated 3/4 city: capital center, blue left, yellow right)
  function hubs() {
    const w = W(), h = H();
    return {
      red: { x: w * 0.50, y: h * 0.42 },
      blue: { x: w * 0.22, y: h * 0.58 },
      yellow: { x: w * 0.78, y: h * 0.58 },
      scout: { x: w * 0.46, y: h * 0.52 },
    };
  }
  const particles = [];
  function addPath(x0, y0, x1, y1, col, n = 18) {
    const mx = (x0 + x1) / 2 + (Math.random() - 0.5) * 40;
    const my = (y0 + y1) / 2 + (Math.random() - 0.5) * 30;
    for (let i = 0; i < n; i++) {
      const t = i / (n - 1), o = 1 - t;
      particles.push({
        x: o * o * x0 + 2 * o * t * mx + t * t * x1,
        y: o * o * y0 + 2 * o * t * my + t * t * y1,
        col, born: performance.now() / 1000 - t * 5,
        life: 8 + Math.random() * 4, phase: Math.random() * 6.28,
      });
    }
  }
  function seedTrails() {
    particles.length = 0;
    const h = hubs();
    // Neural accents #25b8ff / #b04dff + team colours
    for (let i = 0; i < 8; i++) {
      const a = (i / 8) * Math.PI * 2;
      addPath(h.red.x, h.red.y, h.red.x + Math.cos(a) * 160, h.red.y + Math.sin(a) * 90, "255,90,90", 16);
    }
    addPath(h.red.x, h.red.y, h.blue.x, h.blue.y, "37,184,255", 24);   // #25b8ff
    addPath(h.red.x, h.red.y, h.yellow.x, h.yellow.y, "176,77,255", 24); // #b04dff
    addPath(h.blue.x, h.blue.y, h.yellow.x, h.yellow.y, "210,160,90", 20);
    for (let i = 0; i < 6; i++) {
      addPath(h.blue.x, h.blue.y, h.blue.x + (Math.random() - 0.5) * 120, h.blue.y + 40 + Math.random() * 60, "80,160,255", 12);
      addPath(h.yellow.x, h.yellow.y, h.yellow.x + (Math.random() - 0.5) * 120, h.yellow.y + 40 + Math.random() * 60, "255,210,70", 12);
    }
  }
  seedTrails();
  addEventListener("resize", seedTrails);

  (function tickTrails() {
    const now = performance.now() / 1000;
    tctx.clearRect(0, 0, innerWidth, innerHeight);
    for (const p of particles) {
      let age = now - p.born;
      if (age > p.life) { p.born = now; age = 0; }
      const fade = 1 - age / p.life;
      const tw = 0.5 + 0.5 * Math.sin(now * 1.8 + p.phase);
      const a = Math.pow(fade, 1.35) * tw * 0.55;
      if (a < 0.04) continue;
      const r = 0.5 + 0.5 * fade;
      tctx.beginPath();
      tctx.fillStyle = `rgba(${p.col},${(a * 0.3).toFixed(3)})`;
      tctx.arc(p.x, p.y, r * 2.0, 0, Math.PI * 2); tctx.fill();
      tctx.beginPath();
      tctx.fillStyle = `rgba(${p.col},${a.toFixed(3)})`;
      tctx.arc(p.x, p.y, r * 0.65, 0, Math.PI * 2); tctx.fill();
    }
    tctx.lineCap = "round";
    for (let i = 0; i < particles.length - 1; i++) {
      const a = particles[i], b = particles[i + 1];
      if (a.col !== b.col) continue;
      const d = Math.hypot(a.x - b.x, a.y - b.y);
      if (d > 26 || d < 2) continue;
      let age = now - a.born; if (age < 0 || age > a.life) continue;
      const fade = 1 - age / a.life, alpha = Math.pow(fade, 1.3) * 0.25;
      if (alpha < 0.03) continue;
      tctx.beginPath();
      tctx.strokeStyle = `rgba(${a.col},${alpha.toFixed(3)})`;
      tctx.lineWidth = 0.7;
      tctx.moveTo(a.x, a.y); tctx.lineTo(b.x, b.y); tctx.stroke();
    }
    requestAnimationFrame(tickTrails);
  })();

  // Compact badges from live roster, placed around districts (city already has the 3D queens/ants)
  const badgeHost = document.createElement("div");
  badgeHost.id = "kimi-city-badges";
  document.body.appendChild(badgeHost);

  function esc(t) { return String(t ?? "").replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
  function mkBadge(team, s, queen) {
    const d = document.createElement("div");
    d.className = "kimi-badge " + team + (queen ? " queen" : "");
    const top = (s.skills || [])[0] || "";
    d.title = (s.skills || []).slice(0, 6).join(" · ") || s.title || s.name;
    if (queen) d.innerHTML = `<b>${esc(s.name)}</b><span>${esc(s.title || "")}</span>`;
    else d.innerHTML = `<b>${esc(s.name)}</b><span>${esc(top)}</span>`;
    return d;
  }
  function arc(n, cx, cy, r, spread, rows) {
    const out = []; let left = n, i = 0;
    for (let row = 0; row < rows && left > 0; row++) {
      const take = Math.min(left, Math.ceil(left / (rows - row)));
      const rad = r + row * 48;
      for (let k = 0; k < take; k++) {
        const t = take === 1 ? 0.5 : k / (take - 1);
        const ang = -spread / 2 + t * spread - Math.PI / 2;
        out.push({ x: cx + Math.cos(ang) * rad, y: cy + Math.sin(ang) * rad * 0.55 });
        i++; left--;
      }
    }
    return out;
  }

  let data;
  try { data = await (await fetch("/api/soldiers")).json(); } catch (_) { data = { soldiers: [] }; }
  const all = data.soldiers || [];
  const mk = (s) => ({
    name: s.name, title: s.specialty,
    skills: [s.skill && s.skill.name, ...(s.playbooks || []).map(p => p.name)].filter(Boolean),
  });
  const red = all.filter(s => !s.name.startsWith("blue-")).map(mk);
  const blue = all.filter(s => s.name.startsWith("blue-")).map(mk);
  const YELLOW = [
    ["triage", "re-triage"], ["pe", "pe-exe-re"], ["dotnet", "dotnet-re"],
    ["android", "apk-android-re"], ["elf", "elf-macho-re"], ["hex", "hex-firmware-re"],
    ["carve", "re-triage"], ["dos", "dos-mz-16bit-re"], ["dynamic", "dynamic-lab-re"],
  ].map(([name, skill]) => ({ name, title: "RE-Soldat", skills: [skill] }));

  function layoutBadges() {
    badgeHost.innerHTML = "";
    const h = hubs();
    const items = [];
    items.push({ el: mkBadge("red", { name: "ROTE KÖNIGIN", title: "Absolute Herrscherin · All and One", skills: [`${red.length} Soldaten`] }, true), x: h.red.x + 90, y: h.red.y - 30 });
    items.push({ el: mkBadge("red", { name: "Scout", title: "Kniend", skills: ["recon-master"] }, false), x: h.scout.x, y: h.scout.y + 28 });
    items.push({ el: mkBadge("blue", { name: "Blaue Königin", title: "Verteidigung", skills: [`${blue.length} Soldaten`] }, true), x: h.blue.x + 70, y: h.blue.y - 20 });
    items.push({ el: mkBadge("yellow", { name: "Gelbe Königin", title: "RE · Schmiedin", skills: [`${YELLOW.length} Soldaten`] }, true), x: h.yellow.x - 70, y: h.yellow.y - 20 });
    arc(Math.min(red.length, 12), h.red.x, h.red.y + 70, 100, Math.PI * 1.0, 2).forEach((p, i) => {
      items.push({ el: mkBadge("red", red[i], false), x: p.x, y: p.y });
    });
    arc(Math.min(blue.length, 8), h.blue.x, h.blue.y + 55, 70, Math.PI * 0.85, 2).forEach((p, i) => {
      items.push({ el: mkBadge("blue", blue[i], false), x: p.x, y: p.y });
    });
    arc(YELLOW.length, h.yellow.x, h.yellow.y + 55, 70, Math.PI * 0.85, 2).forEach((p, i) => {
      items.push({ el: mkBadge("yellow", YELLOW[i], false), x: p.x, y: p.y });
    });
    for (const it of items) {
      it.el.style.left = it.x + "px";
      it.el.style.top = it.y + "px";
      badgeHost.appendChild(it.el);
    }
  }
  layoutBadges();
  addEventListener("resize", layoutBadges);

  // Click Stadt preset inside iframe when ready (best overview of the metropolis)
  // Preset nur EINMAL setzen – sonst ueberschreibt der 2s-ready-Ping jede Nutzer-Ansicht
  let stadtOnce = false;
  function tryStadt() {
    if (stadtOnce) return;
    try {
      const doc = iframe.contentDocument;
      if (!doc) return;
      const btn = [...doc.querySelectorAll("button")].find(b => /^\s*Stadt\s*$/i.test(b.textContent || ""));
      if (btn) { btn.click(); stadtOnce = true; }
    } catch (_) {}
  }
  iframe.addEventListener("load", () => { setTimeout(tryStadt, 8000); setTimeout(tryStadt, 16000); });
  addEventListener("message", (ev) => {
    if (ev.source !== iframe.contentWindow || ev.origin !== location.origin) return;
    if (ev.data && ev.data.type === "kimi-city" && ev.data.ready) tryStadt();
  });

  window.__ants3d = {
    mode: "kimi-city-embed",
    source: "vendored https://ameisen-3d-welt.kimi.page/",
    red: red.length, blue: blue.length, yellow: YELLOW.length,
    note: "Judith's procedural metropolis (219 buildings, canals, throne) as brain environment",
  };
})().catch(e => console.warn("[ants3d] city embed failed:", e));
